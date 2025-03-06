// Copyright 2025 Yutaro Hayakawa
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"runtime"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/knftables"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

type NetConf struct {
	types.NetConf

	VRFName       string `json:"vrfName"`
	VRFTable      uint32 `json:"vrfTable"`
	ProtocolID    uint8  `json:"protocolID"`
	EnableIPv4    bool   `json:"enableIPv4"`
	EnableIPv6    bool   `json:"enableIPv6"`
	EgressNATMode string `json:"egressNATMode"`
	IsolationMode string `json:"isolationMode"`
}

var (
	dummyGatewayAddressV4 = net.IPv4(169, 254, 0, 1)
)

const (
	// The protocol ID which is not reserved in the /etc/iproute2/rt_protos by default
	defaultProtocolID = 31

	// EgressNATModes
	egressNATModeDisabled = "disabled"
	egressNATModeHostIP   = "hostip"

	// Default priority for the egress NAT ip rule
	egressNATRulePriority = 999

	// IsolationModes
	isolationModeFallthrough = "fallthrough"
	isolationModeIsolated    = "isolated"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(data []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(data, n); err != nil {
		return nil, "", err
	}

	if n.IPAM.Type == "" {
		return nil, "", fmt.Errorf("IPAM plugin must be specified")
	}

	if n.VRFName == "" {
		return nil, "", fmt.Errorf("vrfName is required")
	}

	// The maximum table ID is 65535 (16bit) because we encode the table ID
	// into the conntrack zone which is 16bit.
	if n.VRFTable > math.MaxUint16 {
		return nil, "", fmt.Errorf("vrfTable must be less than or equal to %d", math.MaxUint16)
	}

	if n.ProtocolID == 0 {
		n.ProtocolID = defaultProtocolID
	}

	if !n.EnableIPv4 && !n.EnableIPv6 {
		// If both are disabled, enable both by default
		n.EnableIPv4 = true
		n.EnableIPv6 = true
	}

	if n.EgressNATMode == "" {
		n.EgressNATMode = egressNATModeHostIP
	}

	if n.IsolationMode == "" {
		n.IsolationMode = isolationModeFallthrough
	}

	return n, n.CNIVersion, nil
}

func getVRF(name string) (*netlink.Vrf, error) {
	link, err := netlink.LinkByName(name)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("link %s is not VRF", name)
	}

	return vrf, nil
}

func hasRoute(table uint32) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{
			Table: int(table),
		},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, err
	}
	return len(routes) > 0, nil
}

func findFreeTable(requestedTable uint32) (uint32, error) {
	if requestedTable != 0 {
		found, err := hasRoute(requestedTable)
		if err != nil {
			return 0, err
		}
		if found {
			return 0, fmt.Errorf("requested table (ID: %d) is already in use", requestedTable)
		}
		return requestedTable, nil
	}

	// Table 255 is local table. There's no reserved table for >= 256.
	// Therefore, we'll start from 256. The maximum table ID is 65535
	// (16bit) because we encode the table ID into the conntrack zone which
	// is 16bit.
	for i := uint32(256); i <= math.MaxUint16; i++ {
		found, err := hasRoute(uint32(i))
		if err != nil {
			return 0, err
		}
		if !found {
			return i, nil
		}
	}

	return 0, fmt.Errorf("no available table found")
}

func addVRF(name string, requestedTable uint32) (*netlink.Vrf, error) {
	table, err := findFreeTable(requestedTable)
	if err != nil {
		return nil, err
	}

	err = netlink.LinkAdd(&netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: table,
	})
	if err != nil {
		return nil, err
	}

	vrf, err := getVRF(name)
	if err != nil {
		// We just created the VRF, it's impossible to have error here.
		return nil, err
	}

	if err := netlink.LinkSetUp(vrf); err != nil {
		return nil, fmt.Errorf("failed to set VRF state")
	}

	return vrf, nil
}

func ensureVRF(name string, requestedTable uint32) (*netlink.Vrf, error) {
	var (
		vrf *netlink.Vrf
		err error
	)

	// Try to get an existing VRF
	vrf, err = getVRF(name)
	if vrf == nil && err != nil {
		return nil, fmt.Errorf("failed to get VRF: %w", err)
	}

	// VRF is missing. Create a new one.
	if vrf == nil && err == nil {
		vrf, err = addVRF(name, requestedTable)
		if err != nil {
			return nil, err
		}
	}

	return vrf, nil
}

// ensureUnreachableDefaultRoutes inserts unreachable routes to the VRF device.
// This route is used to isolate the traffic from the VRF device to the outside
// world by default. In Linux, VRF is implemented as an IP rule which is
// evaluated earlier than main routing table. Thus, without this unreachable
// route, the routing lookup falls through to the main table and packets hits
// the routing entries there.
//
// If users wish to direct traffic to other VRFs, they can "leak" the routes
// from other VRFs. They can even override the default route by inserting the
// default route with the priority (metric) lower than 4278198272.
//
// This weird priority value is chosen intentionally based on the FRR's
// implementation. FRR interprets the upper 1 byte as an Administrative
// Distance value and lower 3 bytes as an actual metric. In our case, AD is
// 255. This is a special AD value which will never win the best path
// selection. Please see FRR and Linux VRF's document for more details.
//
// FRR: https://docs.frrouting.org/en/latest/zebra.html#administrative-distance
// Linux VRF: https://www.kernel.org/doc/Documentation/networking/vrf.txt
func ensureUnreachableDefaultRoutes(n *NetConf, vrf *netlink.Vrf) error {
	if n.IsolationMode != isolationModeIsolated {
		return nil
	}

	if n.EnableIPv4 {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			Type:     unix.RTN_UNREACHABLE,
			Priority: 4278198272,
			Table:    int(vrf.Table),
			Protocol: netlink.RouteProtocol(n.ProtocolID),
		}); err != nil {
			return err
		}
	}

	if n.EnableIPv6 {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv6unspecified,
				Mask: net.CIDRMask(0, 128),
			},
			Type:     unix.RTN_UNREACHABLE,
			Priority: 4278198272,
			Table:    int(vrf.Table),
			Protocol: netlink.RouteProtocol(n.ProtocolID),
		}); err != nil {
			return err
		}
	}

	return nil
}

func setupVRF(n *NetConf) (*netlink.Vrf, *current.Interface, error) {
	// create VRF if necessary
	vrf, err := ensureVRF(n.VRFName, n.VRFTable)
	if err != nil {
		return nil, nil, err
	}

	// insert unreachable default route for the isolation
	if err := ensureUnreachableDefaultRoutes(n, vrf); err != nil {
		return nil, nil, fmt.Errorf("failed to insert unreachable default routes to VRF: %w", err)
	}

	return vrf, &current.Interface{
		Name: vrf.Attrs().Name,
		Mac:  vrf.Attrs().HardwareAddr.String(),
	}, nil
}

func setHostVethSysctls(n *NetConf, hostVethLink netlink.Link) error {
	if n.EnableIPv4 {
		// Setup proxy-arp to the host interface
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", hostVethLink.Attrs().Name), "1"); err != nil {
			return fmt.Errorf("failed to set proxy_arp: %w", err)
		}

		// Enable IPv4 forwarding
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/forwarding", hostVethLink.Attrs().Name), "1"); err != nil {
			return fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	if n.EnableIPv6 {
		// Disable IPv6 DAD. We don't need this because this is a point to point link.
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_dad", hostVethLink.Attrs().Name), "0"); err != nil {
			return fmt.Errorf("failed to disable DAD: %w", err)
		}

		// Enable IPv6. This triggers the link-local address generation.
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", hostVethLink.Attrs().Name), "0"); err != nil {
			return fmt.Errorf("failed to enable ipv6: %w", err)
		}

		// Setup proxy-ndp to the host interface
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/proxy_ndp", hostVethLink.Attrs().Name), "1"); err != nil {
			return fmt.Errorf("failed to set proxy_ndp: %w", err)
		}

		// Enable IPv6 forwarding
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/forwarding", hostVethLink.Attrs().Name), "1"); err != nil {
			return fmt.Errorf("failed to set forwarding: %w", err)
		}
	}

	return nil
}

func setContainerVethSysctls(n *NetConf, containerVethLink netlink.Link) error {
	if n.EnableIPv6 {
		// Disable IPv6 DAD. We don't need this because this is a point to point link.
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_dad", containerVethLink.Attrs().Name), "0"); err != nil {
			return fmt.Errorf("failed to disable DAD: %w", err)
		}

		// Enable IPv6. This triggers the link-local address generation
		if _, err := sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", containerVethLink.Attrs().Name), "0"); err != nil {
			return fmt.Errorf("failed to enable ipv6 for veth: %w", err)
		}
	}
	return nil
}

func setDummyGatewayAddressV4(n *NetConf, hostVethLink netlink.Link) error {
	// Assign link-scoped dummy gateway address to the host veth. We need
	// to do this because proxy_arp only replies when the target address is
	// reachable. Since we have a blackhole default route in the VRF table,
	// there's no guarantee that the dummy gateway address is reachable.
	//
	// Note that for IPv6, we don't need to do this because kernel assigns
	// the link-local address automatically.
	return netlink.AddrReplace(hostVethLink, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   dummyGatewayAddressV4,
			Mask: net.CIDRMask(32, 32),
		},
		Scope: int(netlink.SCOPE_LINK),
	})
}

func createVeth(n *NetConf, netns ns.NetNS, vrf *netlink.Vrf, ifName string) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, 0, "", hostNS)
		if err != nil {
			return err
		}

		containerVethLink, err := netlink.LinkByName(containerVeth.Name)
		if err != nil {
			return fmt.Errorf("failed to get container veth: %w", err)
		}

		// We need to enable the container-side veth to get IPv6 link local address
		if err := netlink.LinkSetUp(containerVethLink); err != nil {
			return fmt.Errorf("failed to enable container veth: %w", err)
		}

		// Set sysctls for container veth
		if err := setContainerVethSysctls(n, containerVethLink); err != nil {
			return fmt.Errorf("failed to set container veth sysctls: %w", err)
		}

		// Wait for IPv6 link-local address to be settled
		if n.EnableIPv6 {
			if err := ip.SettleAddresses(containerVeth.Name, 10); err != nil {
				return fmt.Errorf("host veth's IPv6 link-local address didn't appear: %w", err)
			}
		}

		// Fill the CNI result
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// need to lookup hostVethLink again as its index has changed during ns move
	hostVethLink, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVethLink.Attrs().HardwareAddr.String()

	// connect host veth end to the VRF
	if err := netlink.LinkSetMaster(hostVethLink, vrf); err != nil {
		return nil, nil, fmt.Errorf("failed to connect %q to VRF %v: %v", hostVethLink.Attrs().Name, vrf.Attrs().Name, err)
	}

	// Set sysctls for host veth
	if err := setHostVethSysctls(n, hostVethLink); err != nil {
		return nil, nil, fmt.Errorf("failed to set host veth sysctls: %w", err)
	}

	// Set dummy gateway address for IPv4
	if n.EnableIPv4 {
		if err := setDummyGatewayAddressV4(n, hostVethLink); err != nil {
			return nil, nil, fmt.Errorf("failed to assign IPv4 dummy gateway address: %w", err)
		}
	}

	// Wait for IPv6 link-local address to be settled
	if n.EnableIPv6 {
		if err := ip.SettleAddresses(hostIface.Name, 10); err != nil {
			return nil, nil, fmt.Errorf("host veth's IPv6 link-local address didn't appear: %w", err)
		}
	}

	return hostIface, contIface, nil
}

func ensureContainerRoutes(n *NetConf, vrf *netlink.Vrf, hostInterface *current.Interface, result *current.Result) error {
	hostLink, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}

	// Configure direct routes to the addresses provided by the IPAM plugin
	for _, ip := range result.IPs {
		dst := ip.Address

		switch {
		case ip.Address.IP.To4() != nil && n.EnableIPv4:
			dst.Mask = net.CIDRMask(32, 32)
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: hostLink.Attrs().Index,
				Dst:       &dst,
				Table:     int(vrf.Table),
				Scope:     netlink.SCOPE_LINK,
				Protocol:  netlink.RouteProtocol(n.ProtocolID),
			}); err != nil {
				return err
			}
		case ip.Address.IP.To4() == nil && n.EnableIPv6:
			dst.Mask = net.CIDRMask(128, 128)
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: hostLink.Attrs().Index,
				Dst:       &dst,
				Table:     int(vrf.Table),
				Flags:     int(netlink.FLAG_ONLINK),
				Protocol:  netlink.RouteProtocol(n.ProtocolID),
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot setup direct route to the container address %q", ip.Address.IP.String())
		}

	}

	return nil
}

func getDummyGatewayAddresses(n *NetConf, hostInterface *current.Interface) (net.IP, net.IP, error) {
	hostVethLink, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return nil, nil, err
	}

	var v4Gw, v6Gw net.IP

	if n.EnableIPv4 {
		v4Gw = dummyGatewayAddressV4
	}

	if n.EnableIPv6 {
		addrs, err := netlink.AddrList(hostVethLink, netlink.FAMILY_V6)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get IPv6 gateway address: %w", err)
		}
		if len(addrs) != 1 {
			return nil, nil, fmt.Errorf("unexpected number of IPv6 addresses on the host veth: %v", addrs)
		}
		// We should have only one address (link local address) on the host veth at this point
		v6Gw = addrs[0].IP
	}

	return v4Gw, v6Gw, nil
}

func ensureHostRoutes(n *NetConf, netns ns.NetNS, hostInterface, containerInterface *current.Interface, result *current.Result) error {
	// Get IPv4 and IPv6 dummy gateway addresses. For IPv4, it would be a
	// configured one. For IPv6, it's a link local address of the host
	// veth.
	v4Gw, v6Gw, err := getDummyGatewayAddresses(n, hostInterface)
	if err != nil {
		return err
	}

	// IP address should be assigned to the container interface.
	// Fill the Interface field. We also don't provide any L2
	// reachability among containers. Rewrite all addresses to have
	// a maximum prefix length and erase gateway.
	for _, ip := range result.IPs {
		ip.Interface = current.Int(2)

		if ip.Address.IP.To4() != nil {
			ip.Address.Mask = net.CIDRMask(32, 32)
		} else {
			ip.Address.Mask = net.CIDRMask(128, 128)
		}

		ip.Gateway = nil
	}

	// All routes should have dummy gateway address as a nexthop. Override the GW field.
	for _, route := range result.Routes {
		switch {
		case route.Dst.IP.To4() != nil && n.EnableIPv4:
			route.GW = v4Gw
		case route.Dst.IP.To4() == nil && n.EnableIPv6:
			route.GW = v6Gw
		default:
			return fmt.Errorf("route %s doesn't have a suitable gateway address", route.Dst.String())
		}
	}

	// Insert a link-scoped route to the dummy gateway address. We insert
	// this into the beginning of the result.Routes slice because rest of
	// the routes uses the dummy gateway address as a gateway, so the route
	// should be present before the other routes.
	dummyGatewayRoutes := []*types.Route{}
	if n.EnableIPv4 {
		rt := &types.Route{
			Dst: net.IPNet{
				IP:   v4Gw,
				Mask: net.CIDRMask(32, 32),
			},
			Scope: current.Int(int(netlink.SCOPE_LINK)),
		}
		dummyGatewayRoutes = append(dummyGatewayRoutes, rt)
	}

	result.Routes = append(dummyGatewayRoutes, result.Routes...)

	return netns.Do(func(_ ns.NetNS) error {
		return ipam.ConfigureIface(containerInterface.Name, result)
	})
}

func ensureNFTRules(n *NetConf, vrf *netlink.Vrf) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var family knftables.Family

	switch {
	case n.EnableIPv4 && n.EnableIPv6:
		family = knftables.InetFamily
	case n.EnableIPv4:
		family = knftables.IPv4Family
	case n.EnableIPv6:
		family = knftables.IPv6Family
	}

	iface, err := knftables.New(family, "hostvrf-"+n.VRFName)
	if err != nil {
		return err
	}

	tx := iface.NewTransaction()

	// Ensure table
	tx.Add(&knftables.Table{})

	// This flush doesn't disrupt the traffic since the iface.Run
	// uses nft -f internally and the operation is atomic.
	tx.Flush(&knftables.Table{})

	// This rule sets the conntrack zone for the traffic originated from
	// this VRF. We need this rule because we may have an overlapping IP
	// range among VRFs and we may end up having conflicting conntrack
	// entries. This rule should be set regardless of any settings.
	chain := &knftables.Chain{
		Name:     "raw-prerouting",
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.RawPriority),
	}
	tx.Add(chain)
	tx.Add(&knftables.Rule{
		Chain: chain.Name,
		Rule: knftables.Concat(
			"ct zone set", vrf.Table,
			"iif", vrf.Name,
		),
	})

	// Setup Egress NAT
	switch n.EgressNATMode {
	case egressNATModeDisabled:
		// Nothing to do
	case egressNATModeHostIP:
		// This rule masquerades the packets that leaving this VRF. At
		// the same time, it sets the ct mark to indicate which VRF the
		// connection belongs to. This mark will be used by ip rule in
		// the reply path to lookup this VRF's FIB.
		chain = &knftables.Chain{
			Name:     "nat-postrouting",
			Type:     knftables.PtrTo(knftables.NATType),
			Hook:     knftables.PtrTo(knftables.PostroutingHook),
			Priority: knftables.PtrTo(knftables.SNATPriority),
		}
		tx.Add(chain)
		tx.Add(&knftables.Rule{
			Chain: chain.Name,
			Rule: knftables.Concat(
				"iif", vrf.Name,
				"oif !=", vrf.Name,
				"meta l4proto {tcp, udp}",
				"ct mark set", vrf.Table,
				"counter",
				"masquerade",
			),
		})

		// This rule binds reply of the masqueraded traffic to the VRF
		// by setting the mark. We don't need zone for this reply
		// traffic, because the host IP address + port tuple + protocol
		// tuple is unique. This mark will be used by the ip rules to
		// lookup the VRF's routing table.
		chain = &knftables.Chain{
			Name:     "mangle-prerouting",
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.PreroutingHook),
			Priority: knftables.PtrTo(knftables.ManglePriority),
		}
		tx.Add(chain)
		tx.Add(&knftables.Rule{
			Chain: chain.Name,
			Rule: knftables.Concat(
				"iif !=", vrf.Name,
				"meta l4proto {tcp, udp}",
				"ct mark", vrf.Table,
				"counter",
				"meta mark set", vrf.Table,
			),
		})

	default:
		return fmt.Errorf("BUG: Unknown egressNATMode")
	}

	return iface.Run(ctx, tx)
}

func ensureEgressNATIPRules(n *NetConf, vrf *netlink.Vrf) error {
	if n.EgressNATMode != egressNATModeHostIP {
		return nil
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// This rule works in conjunction with the nftables rule in the reply
		// path of the masqueraded packet to lookup this VRF's table when
		// there's specific mark (inherited from the ct mark added in the
		// origin path).
		desiredRule := &netlink.Rule{
			Family: family,
			// This must be lower (prioritized) than main table
			// lookup. For the moment, it is set closer to VRF
			// table lookup (l3mdev rule is priority 1000). Make
			// this configurable if needed.
			Priority: egressNATRulePriority,
			// Mark == TableID
			Table: int(vrf.Table),
			Mark:  uint32(vrf.Table),
			// We need these ugly workarounds because 0 are valid
			// values for these fields. We need to set these fields
			// to -1 to ensure that they are not used in the rule.
			Flow:              -1,
			Goto:              -1,
			SuppressIfgroup:   -1,
			SuppressPrefixlen: -1,
			// Type will be mapped to the Action in the lower level
			Type:     nl.FR_ACT_TO_TBL,
			Protocol: n.ProtocolID,
		}

		rules, err := netlink.RuleListFiltered(
			family,
			desiredRule,
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_MARK,
		)
		if err != nil {
			return fmt.Errorf("list failed: %w", err)
		}
		if len(rules) != 1 {
			// If == 0, it's normal, but if > 1, something wrong is going
			// on here. Delete rules to ensure there's only one rule.
			for _, rule := range rules {
				if err := netlink.RuleDel(&rule); err != nil {
					return fmt.Errorf("delete failed: %w", err)
				}
			}

			if err := netlink.RuleAdd(desiredRule); err != nil {
				return fmt.Errorf("add failed: %w", err)
			}
		}
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	success := false

	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	vrf, vrfInterface, err := setupVRF(n)
	if err != nil {
		return fmt.Errorf("failed to create VRF %q (table: %d): %w", n.VRFName, n.VRFTable, err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := createVeth(n, netns, vrf, args.IfName)
	if err != nil {
		return err
	}

	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			vrfInterface,
			hostInterface,
			containerInterface,
		},
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Release IP in case of failure
	defer func() {
		if !success {
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes
	result.DNS = ipamResult.DNS

	if len(result.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned missing IP config")
	}

	// Make container -> host connectivity
	if err = ensureHostRoutes(n, netns, hostInterface, containerInterface, result); err != nil {
		return fmt.Errorf("failed to setup container to host routes: %w", err)
	}

	// Make host -> container connectivity
	if err = ensureContainerRoutes(n, vrf, hostInterface, result); err != nil {
		return fmt.Errorf("failed to setup host to container routes: %w", err)
	}

	// Ensure nftables rules
	if err = ensureNFTRules(n, vrf); err != nil {
		return fmt.Errorf("failed to setup nftables rules: %w", err)
	}

	// Ensure ip rule required for EgressNAT
	if err = ensureEgressNATIPRules(n, vrf); err != nil {
		return fmt.Errorf("failed to setup ip rules for egress NAT: %w", err)
	}

	// Use incoming DNS settings if provided, otherwise use the
	// settings that were already configured by the IPAM plugin
	if dnsConfSet(n.DNS) {
		result.DNS = n.DNS
	}

	success = true

	return types.PrintResult(result, n.CNIVersion)
}

func dnsConfSet(dnsConf types.DNS) bool {
	return dnsConf.Nameservers != nil ||
		dnsConf.Search != nil ||
		dnsConf.Options != nil ||
		dnsConf.Domain != ""
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	ipamDel := func() error {
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			return err
		}
		return nil
	}

	if args.Netns == "" {
		return ipamDel()
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		// Delete container side veth. This also deletes the host side
		// veth, and any associated host side network resources (direct
		// routes, NDP proxy rules, etc...). Therefore, we don't need
		// to delete them on the host side.
		_, err := ip.DelLinkByNameAddr(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}

		return err
	})
	if err != nil {
		//  if NetNs is passed down by the Cloud Orchestration Engine, or if it called multiple times
		// so don't return an error if the device is already removed.
		// https://github.com/kubernetes/kubernetes/issues/43014#issuecomment-287164444
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return ipamDel()
		}
		return err
	}

	// call ipam.ExecDel after clean up device in netns
	if err := ipamDel(); err != nil {
		return err
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func cmdStatus(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:    cmdAdd,
		Del:    cmdDel,
		Check:  cmdCheck,
		Status: cmdStatus,
	}, version.All, buildversion.BuildString("hostvrf"))
}
