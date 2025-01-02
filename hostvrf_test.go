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
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/require"
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
