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

package types

import (
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

type NetConf struct {
	types.NetConf

	VRFName       string        `json:"vrfName"`
	VRFTable      uint32        `json:"vrfTable"`
	ProtocolID    uint8         `json:"protocolID"`
	EnableIPv4    bool          `json:"enableIPv4"`
	EnableIPv6    bool          `json:"enableIPv6"`
	EgressNATMode string        `json:"egressNATMode"`
	IsolationMode string        `json:"isolationMode"`
	RuntimeConfig RuntimeConfig `json:"runtimeConfig,omitempty"`
}

type RuntimeConfig struct {
	PortMaps []PortMapEntry `json:"portMappings,omitempty"`
}

// PortMapEntry corresponds to a single entry in the port_mappings argument,
// see CONVENTIONS.md
type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

// APIRequest is the request format for the daemon APIs
type APIRequest struct {
	NetConf NetConf        `json:"netConf"`
	Result  current.Result `json:"result"`
}
