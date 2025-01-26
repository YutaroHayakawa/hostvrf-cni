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
	"golang.org/x/sys/unix"
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
				VRFName:               "vrf0",
				VRFTable:              100,
				EnableIPv4:            true,
				EnableIPv6:            true,
				DummyGatewayAddressV4: "169.254.0.1",
				DummyGatewayAddressV6: "fd00::1",
			}),
			expectError: false,
		},
		{
			name: "valid missing enableIPv4",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:    "vrf0",
				VRFTable:   100,
				EnableIPv6: true,
			}),
			expectError: false,
		},
		{
			name: "valid missing enableIPv6",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:    "vrf0",
				VRFTable:   100,
				EnableIPv4: true,
			}),
			expectError: false,
		},
		{
			name: "valid missing dummyGatewayAddressV4",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:               "vrf0",
				VRFTable:              100,
				EnableIPv6:            true,
				DummyGatewayAddressV6: "fd00::1",
			}),
			expectError: false,
		},
		{
			name: "valid missing dummyGatewayAddressV6",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:               "vrf0",
				VRFTable:              100,
				EnableIPv4:            true,
				DummyGatewayAddressV4: "169.254.0.1",
			}),
			expectError: false,
		},
		{
			name: "valid missing dummyGatewayAddressV4 and V6",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:    "vrf0",
				VRFTable:   100,
				EnableIPv4: true,
				EnableIPv6: true,
			}),
			expectError: false,
		},
		{
			name: "valid missing vrfTable",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFName:               "vrf0",
				EnableIPv4:            true,
				DummyGatewayAddressV4: "169.254.0.1",
			}),
		},
		{
			name: "invalid missing vrfName",
			config: marshalConf(t, &NetConf{
				NetConf: types.NetConf{
					IPAM: types.IPAM{
						Type: "foo",
					},
				},
				VRFTable:              100,
				EnableIPv4:            true,
				DummyGatewayAddressV4: "169.254.0.1",
			}),
			expectError: true,
		},
		{
			name: "invalid missing IPAM config",
			config: marshalConf(t, &NetConf{
				VRFName:               "vrf0",
				VRFTable:              100,
				EnableIPv4:            true,
				DummyGatewayAddressV4: "169.254.0.1",
			}),
			expectError: true,
		},
		{
			name: "invalid missing enableIPv4 and enableIPv6",
			config: marshalConf(t, &NetConf{
				VRFName:               "vrf0",
				VRFTable:              100,
				DummyGatewayAddressV4: "169.254.0.1",
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
				Plugins []json.RawMessage
			}{}

			netConfFile := baseDir + "/hostvrf.conflist"

			err = readJSONFile(netConfFile, &confList)
			require.NoError(t, err)

			netConf, _, err := loadNetConf(confList.Plugins[0])
			require.NoError(t, err)

			err = c.Copy(ctx, "hostvrf", "hostvrf", "/go/bin")
			require.NoError(t, err)

			err = c.Copy(ctx, "hostvrf.conflist", netConfFile, "/etc/cni/net.d")
			require.NoError(t, err)

			if netConf.VRFTable == 0 {
				// Insert some random route to "use" table 256
				// (the first available table) to test the
				// table allocation logic. We expect 257 to be
				// allocated.
				err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
					return netlink.RouteAdd(&netlink.Route{
						Dst: &net.IPNet{
							IP:   net.IPv4zero,
							Mask: net.CIDRMask(0, 32),
						},
						Type:  unix.RTN_UNREACHABLE,
						Table: 256,
					})
				})
				require.NoError(t, err)
			}

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
						if netConf.VRFTable != 0 {
							require.Equal(t, netConf.VRFTable, vrf.Table, "Unexpected VRF TableID")
						} else {
							require.Equal(t, uint32(257), vrf.Table, "Unexpected allocated VRF TableID")
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

				t.Run("Sysctls are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.EnableIPv4 {
							v, err := sysctl.Sysctl("net/ipv4/conf/" + hostVeth.Name + "/proxy_arp")
							require.NoError(t, err)
							require.Equal(t, "1", v, "Proxy ARP is not configured on the host side veth")

							v, err = sysctl.Sysctl("net/ipv4/conf/" + hostVeth.Name + "/forwarding")
							require.NoError(t, err)
							require.Equal(t, "1", v, "IPv4 forwarding is not configured on the host side veth")
						}
						if netConf.EnableIPv6 {
							v, err := sysctl.Sysctl("net/ipv6/conf/" + hostVeth.Name + "/proxy_ndp")
							require.NoError(t, err)
							require.Equal(t, "1", v, "Proxy NDP is not configured on the host side veth")

							v, err = sysctl.Sysctl("net/ipv6/conf/" + hostVeth.Name + "/disable_ipv6")
							require.NoError(t, err)
							require.Equal(t, "0", v, "IPv6 is not enabled on the host side veth")

							v, err = sysctl.Sysctl("net/ipv6/conf/" + hostVeth.Name + "/forwarding")
							require.NoError(t, err)
							require.Equal(t, "1", v, "IPv6 forwarding is not enabled on the host side veth")

							neighbors, err := netlink.NeighProxyList(hostVeth.Index, netlink.FAMILY_V6)
							require.NoError(t, err)
							require.Len(t, neighbors, 1, "Proxy NDP neighbor entry is missing")

							expected := net.ParseIP(netConf.DummyGatewayAddressV6)
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
						for _, ip := range addResult.IPs {
							// Whatever the address is, the mask should be 32 for IPv4 and 128 for IPv6
							var ipnet *net.IPNet
							if ip.Address.IP.To4() != nil {
								ipnet = &net.IPNet{
									IP:   ip.Address.IP,
									Mask: net.CIDRMask(32, 32),
								}
							} else {
								ipnet = &net.IPNet{
									IP:   ip.Address.IP,
									Mask: net.CIDRMask(128, 128),
								}
							}

							rt, ok := vrfRoutes[ipnet.String()]
							require.True(t, ok, "Route to the IP %q is not configured", ipnet.String())
							require.Equal(t, rt.LinkIndex, hostVeth.Index, "Route to the IP %q is not bounded to the host veth")

							if ip.Address.IP.To4() != nil {
								require.Equal(t, rt.Scope, netlink.SCOPE_LINK, "Route to the IP %q is not link-scoped")
							} else {
								require.Equal(t, netlink.NextHopFlag(rt.Flags), netlink.FLAG_ONLINK, "Route to the IP %q is not onlink")
							}
						}
						return nil
					})
					require.NoError(t, err)
				})

				t.Run("Unreachable routes are configured", func(t *testing.T) {
					err = c.ExecFunc(ctx, func(_ ns.NetNS) error {
						if netConf.EnableIPv4 {
							rt, ok := vrfRoutes["0.0.0.0/0"]
							require.True(t, ok, "Unreachable default route for IPv4 is not configured")
							require.Equal(t, 4278198272, rt.Priority, "Metric for the unreachable default route for IPv4 must be 4278198272")
						}
						if netConf.EnableIPv6 {
							rt, ok := vrfRoutes["::/0"]
							require.True(t, ok, "Unreachable default route for IPv6 is not configured")
							require.Equal(t, 4278198272, rt.Priority, "Metric for the unreachable default route for IPv6 must be 4278198272")
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

						for _, ip := range addResult.IPs {
							// Whatever the original address is, we assign it with maximum prefix length.
							var ipnet *net.IPNet
							if ip.Address.IP.To4() != nil {
								ipnet = &net.IPNet{
									IP:   ip.Address.IP,
									Mask: net.CIDRMask(32, 32),
								}
							} else {
								ipnet = &net.IPNet{
									IP:   ip.Address.IP,
									Mask: net.CIDRMask(128, 128),
								}
							}
							require.Contains(t, addrMap, ipnet.String(), "Address %q is not assigned to the container interface", ip.Address.IP.String())
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
						if netConf.EnableIPv4 {
							v4NH = net.ParseIP(netConf.DummyGatewayAddressV4)
						}
						if netConf.EnableIPv6 {
							v6NH = net.ParseIP(netConf.DummyGatewayAddressV6)
						}

						for _, route := range addResult.Routes {
							if route.Dst.IP.Equal(v4NH) || route.Dst.IP.Equal(v6NH) {
								continue
							}

							var expectedNexthop net.IP
							if route.Dst.IP.To4() != nil {
								expectedNexthop = v4NH
							} else {
								expectedNexthop = v6NH
							}

							rt, ok := containerRoutes[route.Dst.String()]
							require.True(t, ok, "Route %q is not instantiated", route.Dst)
							require.Equal(t, expectedNexthop.String(), rt.Gw.String(), "Nexthop for the route is wrong")
						}

						return nil
					})
				})

				t.Run("Route to the dummy gateway addresses are instantiated", func(t *testing.T) {
					err = c.ExecFuncInTestingNS(ctx, func(_ ns.NetNS) error {
						if netConf.EnableIPv4 {
							rt, ok := containerRoutes[netConf.DummyGatewayAddressV4+"/32"]
							require.True(t, ok, "IPv4 route to the dummy gateway address is missing")
							require.Equal(t, containerVeth.Index, rt.LinkIndex, "IPv4 route to the dummy gateway address is not bounded to the interface")
							require.Nil(t, rt.Gw, "IPv4 route to the dummy gateway address must not have a gateway")
						}
						if netConf.EnableIPv6 {
							rt, ok := containerRoutes[netConf.DummyGatewayAddressV6+"/128"]
							require.True(t, ok, "IPv6 route to the dummy gateway address is missing")
							require.Equal(t, containerVeth.Index, rt.LinkIndex, "IPv6 route to the dummy gateway address is not bounded to the interface")
							require.Nil(t, rt.Gw, "IPv6 route to the dummy gateway address must not have a gateway")
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
						table := netConf.VRFTable
						if table == 0 {
							// Dynamic allocation case
							table = 257
						}
						if netConf.EnableIPv4 {
							routes := map[string]netlink.Route{}
							err := netlink.RouteListFilteredIter(
								netlink.FAMILY_V4,
								&netlink.Route{
									Table: int(table),
								},
								netlink.RT_FILTER_TABLE,
								func(rt netlink.Route) bool {
									routes[rt.Dst.String()] = rt
									return true
								},
							)
							require.NoError(t, err)
							require.Len(t, routes, 1, "Unexpected number of IPv4 routes are left")
							require.Contains(t, routes, "0.0.0.0/0", "Unreachable default route is missing after DEL")
						}
						if netConf.EnableIPv6 {
							routes := map[string]netlink.Route{}
							err := netlink.RouteListFilteredIter(
								netlink.FAMILY_V6,
								&netlink.Route{
									Table: int(table),
								},
								netlink.RT_FILTER_TABLE,
								func(rt netlink.Route) bool {
									routes[rt.Dst.String()] = rt
									return true
								},
							)
							require.NoError(t, err)
							require.Len(t, routes, 1, "Unexpected number of IPv6 routes are left")
							require.Contains(t, routes, "::/0", "Unreachable default route is missing after DEL")
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
