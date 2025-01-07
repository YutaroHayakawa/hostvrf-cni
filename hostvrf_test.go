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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func marshalConf(t *testing.T, n *NetConf) []byte {
	t.Helper()
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal("cannot marshal config")
	}
	return data
}

// TestLoadNetConf tests the validation in the loadNetConf.
func TestLoadNetConf(t *testing.T) {
	tests := []struct {
		name        string
		config      []byte
		expectError bool
	}{
		{
			name: "valid",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:           "vrf0",
				VRFTable:          100,
				LoopbackAddressV4: "169.254.0.1",
				LoopbackAddressV6: "fd00::1",
			}),
			expectError: false,
		},
		{
			name: "valid missing loopbackAddressV4",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:           "vrf0",
				VRFTable:          100,
				LoopbackAddressV6: "fd00::1",
			}),
			expectError: false,
		},
		{
			name: "valid missing loopbackAddressV6",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:           "vrf0",
				VRFTable:          100,
				LoopbackAddressV4: "169.254.0.1",
			}),
			expectError: false,
		},
		{
			name: "invalid missing vrfName",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFTable:          100,
				LoopbackAddressV4: "169.254.0.1",
			}),
			expectError: true,
		},
		{
			name: "invalid missing vrfTable",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:           "vrf0",
				LoopbackAddressV4: "169.254.0.1",
			}),
			expectError: true,
		},
		{
			name: "invalid missing loopbackAddressV4 and V6",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:  "vrf0",
				VRFTable: 100,
			}),
			expectError: true,
		},
		{
			name: "invalid missing IPAM config",
			config: marshalConf(t, &NetConf{
				VRFName:           "vrf0",
				VRFTable:          100,
				LoopbackAddressV4: "169.254.0.1",
			}),
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := loadNetConf(test.config)
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type testNetConf struct {
	VRFName           string `json:"vrfName"`
	VRFTable          uint32 `json:"vrfTable"`
	LoopbackAddressV4 string `json:"loopbackAddressV4,omitempty"`
	LoopbackAddressV6 string `json:"loopbackAddressV6,omitempty"`

	IPAM testIPAMConf
}

type testIPAMConf struct {
	Addresses []testIPAMAddresses
	Routes    []testIPAMRoute
}

type testIPAMAddresses struct {
	Address string `json:"address"`
}

type testIPAMRoute struct {
	Dst string `json:"dst"`
}

const testRunnerImage = "localhost/hostvrf-tester:local"

type testRunner struct {
	d  *docker.Client
	id string
}

func runTesterContainer(ctx context.Context) (*testRunner, error) {
	d, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	createRes, err := d.ContainerCreate(
		ctx,
		&container.Config{
			Image:           testRunnerImage,
			NetworkDisabled: true,
		},
		&container.HostConfig{
			Privileged: true,
		},
		nil,
		nil,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	if err = d.ContainerStart(ctx, createRes.ID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	return &testRunner{
		d:  d,
		id: createRes.ID,
	}, nil
}

func (r *testRunner) Close(ctx context.Context) error {
	if err := r.d.ContainerKill(ctx, r.id, ""); err != nil {
		return fmt.Errorf("failed to kill container: %w", err)
	}
	if err := r.d.ContainerRemove(ctx, r.id, container.RemoveOptions{}); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}
	if err := r.d.Close(); err != nil {
		return fmt.Errorf("failed to close docker client: %w", err)
	}
	return nil
}

func (r *testRunner) Copy(ctx context.Context, name, src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0755,
		Size: int64(len(data)),
	}); err != nil {
		return err
	}

	if _, err := tw.Write(data); err != nil {
		return err
	}

	if err := r.d.CopyToContainer(ctx, r.id, dst, &buf, container.CopyToContainerOptions{}); err != nil {
		return err
	}

	return nil
}

type ExecOpt func(o *container.ExecOptions)

func WithEnv(env []string) ExecOpt {
	return func(o *container.ExecOptions) {
		o.Env = env
	}
}

func (r *testRunner) Exec(ctx context.Context, cmds []string, opts ...ExecOpt) (*bytes.Buffer, *bytes.Buffer, error) {
	var stdout, stderr bytes.Buffer

	execOptions := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmds,
	}

	for _, opt := range opts {
		opt(&execOptions)
	}

	execID, err := r.d.ContainerExecCreate(ctx, r.id, execOptions)
	if err != nil {
		return &stdout, &stderr, err
	}

	resp, err := r.d.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return &stdout, &stderr, err
	}
	defer resp.Close()

	_, err = stdcopy.StdCopy(&stdout, &stderr, resp.Reader)
	if err != nil {
		return &stdout, &stderr, err
	}

	inspect, err := r.d.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return &stdout, &stderr, err
	}

	if inspect.ExitCode != 0 {
		return &stdout, &stderr, fmt.Errorf("cmd failed: %d", inspect.ExitCode)
	}

	return &stdout, &stderr, err
}

func (r *testRunner) ExecJSON(ctx context.Context, v any, cmds []string, opts ...ExecOpt) (*bytes.Buffer, error) {
	stdout, stderr, err := r.Exec(ctx, cmds, opts...)
	if err != nil {
		return stderr, err
	}

	if err := json.Unmarshal(stdout.Bytes(), v); err != nil {
		return stderr, fmt.Errorf("failed to unmarshal result")
	}

	return stderr, err
}

func (r *testRunner) ExecFunc(ctx context.Context, toRun func(ns.NetNS) error) error {
	containerJSON, err := r.d.ContainerInspect(ctx, r.id)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	if containerJSON.ContainerJSONBase == nil || containerJSON.ContainerJSONBase.State == nil {
		return fmt.Errorf("failed to resolve network namespace path")
	}

	netnsPath := fmt.Sprintf("/proc/%d/ns/net", containerJSON.ContainerJSONBase.State.Pid)

	return ns.WithNetNSPath(netnsPath, toRun)
}

func (r *testRunner) ExecFuncInTestingNS(ctx context.Context, toRun func(ns.NetNS) error) error {
	// First get the container's PID
	containerJSON, err := r.d.ContainerInspect(ctx, r.id)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	if containerJSON.ContainerJSONBase == nil || containerJSON.State == nil {
		return fmt.Errorf("failed to resolve network namespace path")
	}

	// Assuming there's a child process running within the "testing" netns
	// (see the ENTRYPOINT in the Dockerfile, get a PID of it.
	pid := containerJSON.State.Pid
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)

	data, err := os.ReadFile(childrenPath)
	if err != nil {
		return fmt.Errorf("failed to read children pids: %w", err)
	}

	// Assume there's only one child process. The children file contains
	// the space-separated list of child process PIDs. Even there's only
	// one child process, there's a space at the end. That's why we check
	// for len(spl) != 2 here.
	spl := strings.Split(string(data), " ")
	if len(spl) != 2 {
		return fmt.Errorf("failed to split children pid file")
	}

	// Execute the code in the context of the child process ("testing" netns)
	return ns.WithNetNSPath(fmt.Sprintf("/proc/%s/ns/net", spl[0]), toRun)
}

func readJSONFile(name string, v any) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err = json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal file: %w", err)
	}

	return err
}

func validateAndNormalizeRandomFields(t *testing.T, result *current.Result) {
	// [0] = VRF, [1] = Host Veth, [2] = Container Veth
	require.Len(t, result.Interfaces, 3)

	// Host interface name must start with "veth". We only check prefix
	// here because the host side veth's name is random except the "veth"
	// prefix.
	require.True(t, strings.HasPrefix(
		result.Interfaces[1].Name, "veth"),
		"Host side veth (result.interfaces[1]) name must have prefix \"veth\" (actual: %s)",
		result.Interfaces[1].Name,
	)

	// Normalize the interface name for later comparison
	result.Interfaces[1].Name = "veth00000000"

	for _, iface := range result.Interfaces {
		require.NotEmpty(t, iface, "mac must be set")

		// mac field must be a valid MAC address. We only check the
		// format here because the mac address is random.
		_, err := net.ParseMAC(iface.Mac)
		require.NoError(t, err, "mac %s is not a valid MAC address", iface.Mac)

		// Normalize the MAC address for later comparison
		iface.Mac = "00:00:00:00:00:00"
	}
}

func TestCNIAddDel(t *testing.T) {
	ctx := context.TODO()
	datadir := "./testdata/adddel"

	d, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	require.NoError(t, err)

	t.Cleanup(func() {
		d.Close()
	})

	dirs, err := os.ReadDir(datadir)
	require.NoError(t, err)

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}

		t.Run(dir.Name(), func(t *testing.T) {
			baseDir := datadir + "/" + dir.Name()

			c, err := runTesterContainer(ctx)
			require.NoError(t, err)

			t.Cleanup(func() {
				if err = c.Close(context.TODO()); err != nil {
					t.Fatalf("Failed to cleanup tester container %q. Please cleanup manually.", c.id)
				}
			})

			confList := struct {
				Plugins []testNetConf
			}{}

			netConfFile := baseDir + "/hostvrf.conflist"

			err = readJSONFile(netConfFile, &confList)
			require.NoError(t, err)

			netConf := confList.Plugins[0]

			err = c.Copy(ctx, "hostvrf", "hostvrf", "/go/bin")
			require.NoError(t, err)

			err = c.Copy(ctx, "hostvrf.conflist", netConfFile, "/etc/cni/net.d")
			require.NoError(t, err)

			var addResult current.Result

			t.Run("ADD", func(t *testing.T) {
				t.Run("Output", func(t *testing.T) {
					var expectedResult current.Result

					err = readJSONFile(baseDir+"/result.json", &expectedResult)
					require.NoError(t, err)

					stderr, err := c.ExecJSON(
						ctx,
						&addResult,
						[]string{"cnitool", "add", "hostvrf", "/var/run/netns/testing"},
						WithEnv([]string{"CNI_PATH=/go/bin"}),
					)
					require.NoError(t, err, "stderr: %s", stderr.String())

					validateAndNormalizeRandomFields(t, &addResult)

					require.Equal(t, expectedResult, addResult)
				})

				var vrf *netlink.Vrf

				t.Run("VRF configuration is correct", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						vrfLink, err := netlink.LinkByName(netConf.VRFName)
						require.NoError(t, err, "VRF is missing")
						require.True(t, vrfLink.Attrs().Flags&net.FlagUp > 0, "VRF is not up")
						vrf = vrfLink.(*netlink.Vrf)
						require.Equal(t, netConf.VRFTable, vrf.Table, "Unexpected VRF TableID")
						return nil
					})
					require.NoError(t, err)
				})

				t.Run("VRF loopback IPs are assigned", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.LoopbackAddressV4 != "" {
							addrs, err := netlink.AddrList(vrf, netlink.FAMILY_V4)
							require.NoError(t, err)
							require.Len(t, addrs, 1, "IPv4 loopback address is missing")
							expected := net.ParseIP(netConf.LoopbackAddressV4)
							require.NotNil(t, expected)
							require.Equal(t, expected.String(), addrs[0].IP.String(),
								"Unexpected IPv4 loopback address %q is assigned to the VRF", addrs[0].IP.String())
						}
						if netConf.LoopbackAddressV6 != "" {
							addrs, err := netlink.AddrList(vrf, netlink.FAMILY_V6)
							require.NoError(t, err)
							require.Len(t, addrs, 1, "IPv6 loopback address is missing")
							expected := net.ParseIP(netConf.LoopbackAddressV6)
							require.NotNil(t, expected)
							require.Equal(t, expected.String(), addrs[0].IP.String(),
								"Unexpected IPv6 loopback address %q is assigned to the VRF", addrs[0].IP.String())
						}
						return nil
					})
					require.NoError(t, err)
				})

				var hostVeth *netlink.Veth

				t.Run("Host-side veth is enslaved to the VRF", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						// List all devices enslaved to the VRF
						links, err := netlink.LinkList()
						require.NoError(t, err)
						enslavedLinks := []netlink.Link{}
						for _, link := range links {
							if link.Attrs().MasterIndex != vrf.Index {
								continue
							}
							enslavedLinks = append(enslavedLinks, link)
						}

						// Currently, we assume only one container
						require.Len(t, enslavedLinks, 1, "Host side interface is not enslaved to the VRF")

						hostVeth = enslavedLinks[0].(*netlink.Veth)

						return nil
					})
					require.NoError(t, err)
				})

				t.Run("Proxy ARP/NDP are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.LoopbackAddressV4 != "" {
							v, err := sysctl.Sysctl("net/ipv4/conf/" + hostVeth.Name + "/proxy_arp")
							require.NoError(t, err)
							require.Equal(t, "1", v, "Proxy ARP is not configured on the host side veth")
						}
						if netConf.LoopbackAddressV6 != "" {
							v, err := sysctl.Sysctl("net/ipv6/conf/" + hostVeth.Name + "/proxy_ndp")
							require.NoError(t, err)
							require.Equal(t, "1", v, "Proxy NDP is not configured on the host side veth")

							neighbors, err := netlink.NeighProxyList(hostVeth.Index, netlink.FAMILY_V6)
							require.NoError(t, err)
							require.Len(t, neighbors, 1, "Proxy NDP neighbor entry is missing")

							expected := net.ParseIP(netConf.LoopbackAddressV6)
							require.NotNil(t, expected)
							require.True(t, neighbors[0].IP.Equal(expected), "Proxy NDP is set for the wrong IP: %s", neighbors[0].IP.String())
						}
						return nil
					})
					require.NoError(t, err)
				})

				vrfRoutes := map[string]netlink.Route{}

				err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
					err := netlink.RouteListFilteredIter(
						netlink.FAMILY_ALL,
						&netlink.Route{
							Table: int(vrf.Table),
						},
						netlink.RT_FILTER_TABLE,
						func(rt netlink.Route) bool {
							vrfRoutes[rt.Dst.String()] = rt
							return true
						},
					)
					require.NoError(t, err)
					return nil
				})
				require.NoError(t, err)

				t.Run("Direct route to the containers are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						for _, address := range netConf.IPAM.Addresses {
							ip, _, err := net.ParseCIDR(address.Address)
							require.NoError(t, err)

							// Whatever the address is, the mask should be 32 for IPv4 and 128 for IPv6
							var ipnet *net.IPNet
							if ip.To4() != nil {
								ipnet = &net.IPNet{
									IP:   ip,
									Mask: net.CIDRMask(32, 32),
								}
							} else {
								ipnet = &net.IPNet{
									IP:   ip,
									Mask: net.CIDRMask(128, 128),
								}
							}

							rt, ok := vrfRoutes[ipnet.String()]
							require.True(t, ok, "Route to the IP %q is not configured", address.Address)
							require.Equal(t, rt.LinkIndex, hostVeth.Index, "Route to the IP %q is not bounded to the host veth")

							if ip.To4() != nil {
								require.Equal(t, rt.Scope, netlink.SCOPE_LINK, "Route to the IP %q is not link-scoped")
							} else {
								require.Equal(t, netlink.NextHopFlag(rt.Flags), netlink.FLAG_ONLINK, "Route to the IP %q is not onlink")
							}
						}
						return nil
					})
					require.NoError(t, err)
				})

				t.Run("Blackhole routes are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.LoopbackAddressV4 != "" {
							rt, ok := vrfRoutes["0.0.0.0/0"]
							require.True(t, ok, "Blackhole default route for IPv4 is not configured")
							require.Equal(t, 100, rt.Priority, "Metric for the blackhole default route for IPv4 should be 100")
						}
						if netConf.LoopbackAddressV6 != "" {
							rt, ok := vrfRoutes["::/0"]
							require.True(t, ok, "Blackhole default route for IPv4 is not configured")
							require.Equal(t, 100, rt.Priority, "Metric for the blackhole default route for IPv4 should be 100")
						}
						return nil
					})
					require.NoError(t, err)
				})

				t.Run("Container IP addresses are assigned", func(t *testing.T) {
					err = c.ExecFuncInTestingNS(ctx, func(_ ns.NetNS) error {
						link, err := netlink.LinkByName("eth0")
						require.NoError(t, err)

						addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
						require.NoError(t, err)

						addrMap := map[string]netlink.Addr{}
						for _, addr := range addrs {
							addrMap[addr.IPNet.String()] = addr
						}

						for _, addr := range netConf.IPAM.Addresses {
							p, err := netip.ParsePrefix(addr.Address)
							require.NoError(t, err)

							// Whatever the original address is, we assign it with maximum prefix length.
							if p.Addr().Is4() {
								p, err = p.Addr().Prefix(32)
								require.NoError(t, err)
							} else {
								p, err = p.Addr().Prefix(128)
								require.NoError(t, err)
							}

							_, ok := addrMap[p.String()]
							require.True(t, ok, "Address %q is not assigned to the container interface", addr.Address)
						}

						return nil
					})
					require.NoError(t, err)
				})

				var containerVeth *netlink.Veth

				containerRoutes := map[string]netlink.Route{}
				err = c.ExecFuncInTestingNS(ctx, func(_ ns.NetNS) error {
					link, err := netlink.LinkByName("eth0")
					require.NoError(t, err)

					containerVeth = link.(*netlink.Veth)

					routes, err := netlink.RouteList(containerVeth, netlink.FAMILY_ALL)
					require.NoError(t, err)

					for _, route := range routes {
						containerRoutes[route.Dst.String()] = route
					}

					return nil
				})
				require.NoError(t, err)

				t.Run("Container routes are instantiated", func(t *testing.T) {
					err = c.ExecFuncInTestingNS(ctx, func(_ ns.NetNS) error {
						var v4NH, v6NH net.IP
						if netConf.LoopbackAddressV4 != "" {
							v4NH = net.ParseIP(netConf.LoopbackAddressV4)
						}
						if netConf.LoopbackAddressV6 != "" {
							v6NH = net.ParseIP(netConf.LoopbackAddressV6)
						}

						for _, route := range netConf.IPAM.Routes {
							p, err := netip.ParsePrefix(route.Dst)
							require.NoError(t, err)

							var expectedNexthop net.IP
							if p.Addr().Is4() {
								expectedNexthop = v4NH
							} else {
								expectedNexthop = v6NH
							}

							rt, ok := containerRoutes[p.String()]
							require.True(t, ok, "Route %q is not instantiated", route.Dst)
							require.Equal(t, expectedNexthop.String(), rt.Gw.String(), "Nexthop for the route is wrong")
						}

						return nil
					})
				})

				t.Run("Route to the loopback addresses are instantiated", func(t *testing.T) {
					err = c.ExecFuncInTestingNS(ctx, func(_ ns.NetNS) error {
						if netConf.LoopbackAddressV4 != "" {
							rt, ok := containerRoutes[netConf.LoopbackAddressV4+"/32"]
							require.True(t, ok, "IPv4 route to the loopback address is missing")
							require.Equal(t, containerVeth.Index, rt.LinkIndex, "IPv4 route to the loopback address is not bounded to the interface")
							require.Nil(t, rt.Gw, "IPv4 route to the loopback address must not have a gateway")
						}
						if netConf.LoopbackAddressV6 != "" {
							rt, ok := containerRoutes[netConf.LoopbackAddressV6+"/128"]
							require.True(t, ok, "IPv6 route to the loopback address is missing")
							require.Equal(t, containerVeth.Index, rt.LinkIndex, "IPv6 route to the loopback address is not bounded to the interface")
							require.Nil(t, rt.Gw, "IPv6 route to the loopback address must not have a gateway")
						}
						return nil
					})
				})
			})

			t.Run("DEL", func(t *testing.T) {
				t.Run("Run DEL", func(t *testing.T) {
					stdout, stderr, err := c.Exec(
						ctx,
						[]string{"cnitool", "del", "hostvrf", "/var/run/netns/testing"},
						WithEnv([]string{"CNI_PATH=/go/bin"}),
					)
					require.NoError(t, err, "stdout: %s\nstderr: %s", stdout.String(), stderr.String())
				})

				t.Run("No device is enslaved to the VRF", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						// List all devices enslaved to the VRF
						vrfLink, err := netlink.LinkByName(netConf.VRFName)
						require.NoError(t, err)

						links, err := netlink.LinkList()
						require.NoError(t, err)

						enslavedLinks := []netlink.Link{}
						for _, link := range links {
							if link.Attrs().MasterIndex != vrfLink.Attrs().Index {
								continue
							}
							enslavedLinks = append(enslavedLinks, link)
						}

						require.Empty(t, enslavedLinks, "One or more devices are still enslaved to the VRF")

						return nil
					})
				})

				t.Run("No direct route to the containers are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.LoopbackAddressV4 != "" {
							routes := map[string]netlink.Route{}
							err := netlink.RouteListFilteredIter(
								netlink.FAMILY_V4,
								&netlink.Route{
									Table: int(netConf.VRFTable),
								},
								netlink.RT_FILTER_TABLE,
								func(rt netlink.Route) bool {
									routes[rt.Dst.String()] = rt
									return true
								},
							)
							require.NoError(t, err)
							require.Len(t, routes, 2, "Unexpected number of IPv4 routes are left")
							require.Contains(t, routes, "0.0.0.0/0", "Blackhole default route is missing after DEL")
							require.Contains(t, routes, netConf.LoopbackAddressV4+"/32", "Loopback route is missing after DEL")
						}
						if netConf.LoopbackAddressV6 != "" {
							routes := map[string]netlink.Route{}
							err := netlink.RouteListFilteredIter(
								netlink.FAMILY_V6,
								&netlink.Route{
									Table: int(netConf.VRFTable),
								},
								netlink.RT_FILTER_TABLE,
								func(rt netlink.Route) bool {
									routes[rt.Dst.String()] = rt
									return true
								},
							)
							require.NoError(t, err)
							require.Len(t, routes, 2, "Unexpected number of IPv6 routes are left")
							require.Contains(t, routes, "::/0", "Blackhole default route is missing after DEL")
							require.Contains(t, routes, netConf.LoopbackAddressV6+"/128", "Loopback route is missing after DEL")
						}
						return nil
					})
				})

				t.Run("Run second DEL doesn't fail", func(t *testing.T) {
					stdout, stderr, err := c.Exec(
						ctx,
						[]string{"cnitool", "del", "hostvrf", "/var/run/netns/testing"},
						WithEnv([]string{"CNI_PATH=/go/bin"}),
					)
					require.NoError(t, err, "stdout: %s\nstderr: %s", stdout.String(), stderr.String())
				})
			})
		})
	}
}
