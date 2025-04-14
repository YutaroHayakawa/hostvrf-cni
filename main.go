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
	_ "embed"
	"log/slog"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"

	"github.com/YutaroHayakawa/hostvrf-cni/internal/cniinstaller"
)

var (
	// We embed the CNI binary here because we cannot embed it from
	// cniinstaller package.
	//
	//go:embed plugins/hostvrf/hostvrf
	cniBin []byte

	Hive = hive.New(
		cniinstaller.Cell,
		cell.Provide(func() cniinstaller.CNIBinary { return cniBin }),
	)

	cmd = &cobra.Command{
		Use: "hostvrf-cni",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := Hive.Run(slog.Default()); err != nil {
				return err
			}
			return nil
		},
	}
)

func main() {
	Hive.RegisterFlags(cmd.Flags())

	cmd.AddCommand(
		Hive.Command(),
	)

	cmd.Execute()
}
