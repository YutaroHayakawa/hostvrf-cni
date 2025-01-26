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
	"encoding/json"
	"fmt"
	"math"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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

	VRFName               string `json:"vrfName"`
	VRFTable              uint32 `json:"vrfTable"`
	EnableIPv4            bool   `json:"enableIPv4"`
	EnableIPv6            bool   `json:"enableIPv6"`
	DummyGatewayAddressV4 string `json:"dummyGatewayAddressV4"`
	DummyGatewayAddressV6 string `json:"dummyGatewayAddressV6"`

	// Private fields used internally. Filled at the load time.
	dummyGatewayAddressV4 net.IP `json:"-"`
	dummyGatewayAddressV6 net.IP `json:"-"`
}

const (
	defaultDummyGatewayAddressV4 = "169.254.0.1"
	defaultDummyGatewayAddressV6 = "fd00:169:254::1"
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

	if !n.EnableIPv4 && !n.EnableIPv6 {
		return nil, "", fmt.Errorf("either IPv4 or IPv6 must be enabled")
	}

	if n.DummyGatewayAddressV4 == "" {
		n.DummyGatewayAddressV4 = defaultDummyGatewayAddressV4
	}

	if n.DummyGatewayAddressV6 == "" {
		n.DummyGatewayAddressV6 = defaultDummyGatewayAddressV6
	}

	dummyGatewayAddressV4 := net.ParseIP(n.DummyGatewayAddressV4)
	if dummyGatewayAddressV4 == nil {
		return nil, "", fmt.Errorf("failed to parse IPv4 dummy gateway address %q", n.DummyGatewayAddressV4)
	}
	if dummyGatewayAddressV4.To4() == nil {
		return nil, "", fmt.Errorf("dummyGatewayAddressV4 must be an IPv4 address")
	}
	n.dummyGatewayAddressV4 = dummyGatewayAddressV4

	dummyGatewayAddressV6 := net.ParseIP(n.DummyGatewayAddressV6)
	if dummyGatewayAddressV6 == nil {
		return nil, "", fmt.Errorf("failed to parse IPv6 dummy gateway address %q", n.DummyGatewayAddressV6)
	}
	if dummyGatewayAddressV6.To4() != nil {
		return nil, "", fmt.Errorf("dummyGatewayAddressV6 must be an IPv6 address")
	}
	n.dummyGatewayAddressV6 = dummyGatewayAddressV6

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
	// Therefore, we'll start from 256.
	for i := uint32(256); i < math.MaxUint32; i++ {
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
	if n.EnableIPv4 {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			Type:     unix.RTN_UNREACHABLE,
			Priority: 4278198272,
			Table:    int(vrf.Table),
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

func setupVeth(netns ns.NetNS, vrf *netlink.Vrf, ifName string) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, 0, "", hostNS)
		if err != nil {
			return err
		}
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

	return hostIface, contIface, nil
}

func ensureContainerRoutes(n *NetConf, vrf *netlink.Vrf, hostInterface *current.Interface, result *current.Result) error {
	hostLink, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}

	hostVeth, ok := hostLink.(*netlink.Veth)
	if !ok {
		return fmt.Errorf("failed to convert link to veth")
	}

	if n.EnableIPv4 {
		// setup proxy-arp to the host interface
		if _, err = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/proxy_arp", hostVeth.Name), "1"); err != nil {
			return fmt.Errorf("failed to set proxy_arp: %w", err)
		}
	}

	if n.EnableIPv6 {
		// setup proxy-ndp to the host interface
		if _, err = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/proxy_ndp", hostVeth.Name), "1"); err != nil {
			return fmt.Errorf("failed to set proxy_ndp: %w", err)
		}

		// For IPv6, we need to setup the neighbor entry for proxying
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:   hostVeth.Index,
			Family:      netlink.FAMILY_V6,
			State:       netlink.NUD_PERMANENT,
			IP:          n.dummyGatewayAddressV6,
			Flags:       netlink.NTF_PROXY,
			MasterIndex: vrf.Index,
		}); err != nil {
			return fmt.Errorf("failed to set proxy-ndp neighbor entry: %w", err)
		}
	}

	// Configure direct routes to the addresses provided by the IPAM plugin
	for _, ip := range result.IPs {
		dst := ip.Address

		switch {
		case ip.Address.IP.To4() != nil && n.EnableIPv4:
			dst.Mask = net.CIDRMask(32, 32)
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: hostVeth.Index,
				Dst:       &dst,
				Table:     int(vrf.Table),
				Scope:     netlink.SCOPE_LINK,
			}); err != nil {
				return err
			}
		case ip.Address.IP.To4() == nil && n.EnableIPv6:
			dst.Mask = net.CIDRMask(128, 128)
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: hostVeth.Index,
				Dst:       &dst,
				Table:     int(vrf.Table),
				Flags:     int(netlink.FLAG_ONLINK),
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot setup direct route to the container address %q", ip.Address.IP.String())
		}

	}

	return nil
}

func ensureHostRoutes(n *NetConf, netns ns.NetNS, containerInterface *current.Interface, result *current.Result) error {
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
			route.GW = n.dummyGatewayAddressV4
		case route.Dst.IP.To4() == nil && n.EnableIPv6:
			route.GW = n.dummyGatewayAddressV6
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
				IP:   n.dummyGatewayAddressV4,
				Mask: net.CIDRMask(32, 32),
			},
			Scope: current.Int(int(netlink.SCOPE_LINK)),
		}
		dummyGatewayRoutes = append(dummyGatewayRoutes, rt)
	}
	if n.EnableIPv6 {
		rt := &types.Route{
			Dst: net.IPNet{
				IP:   n.dummyGatewayAddressV6,
				Mask: net.CIDRMask(128, 128),
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

	hostInterface, containerInterface, err := setupVeth(netns, vrf, args.IfName)
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
	if err = ensureHostRoutes(n, netns, containerInterface, result); err != nil {
		return fmt.Errorf("failed to setup container to host routes: %w", err)
	}

	// Make host -> container connectivity
	if err = ensureContainerRoutes(n, vrf, hostInterface, result); err != nil {
		return fmt.Errorf("failed to setup host to container routes: %w", err)
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
