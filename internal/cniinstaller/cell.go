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

package cniinstaller

import (
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"cni-installer",
	"CNI binary installer",
	cell.Config(defaultCfg),
	cell.Provide(newCNIInstaller),
	cell.Invoke(func(_ *CNIInstaller) {}),
)

var defaultCfg = Config{
	CNIPath:            "/opt/cni/bin",
	RemoveBinaryOnExit: false,
}

type Config struct {
	CNIPath            string
	RemoveBinaryOnExit bool
}

func (cfg Config) Flags(fs *pflag.FlagSet) {
	fs.String(
		"cni-path",
		defaultCfg.CNIPath,
		"CNI plugin path",
	)
	fs.Bool(
		"remove-binary-on-exit",
		defaultCfg.RemoveBinaryOnExit,
		"Remove CNI binary on exit",
	)
}

type CNIInstaller struct {
	logger    *slog.Logger
	cfg       Config
	cniBinary CNIBinary
}

type CNIBinary []byte

type in struct {
	cell.In

	Logger    *slog.Logger
	Cfg       Config
	Lifecycle cell.Lifecycle
	CNIBinary CNIBinary
}

func newCNIInstaller(in in) *CNIInstaller {
	c := &CNIInstaller{
		logger:    in.Logger,
		cfg:       in.Cfg,
		cniBinary: in.CNIBinary,
	}
	in.Lifecycle.Append(c)
	return c
}

func (c *CNIInstaller) cniBinaryPath(cniPath string) string {
	return cniPath + "/hostvrf"
}

func (c *CNIInstaller) Start(_ cell.HookContext) error {
	path := c.cniBinaryPath(c.cfg.CNIPath)

	// Write the CNI binary to the specified path
	if err := os.WriteFile(path, []byte(c.cniBinary), 0755); err != nil {
		return err
	}

	// Ensure permissions are set correctly
	if err := os.Chmod(path, 0755); err != nil {
		return err
	}

	return nil
}

func (c *CNIInstaller) Stop(_ cell.HookContext) error {
	if c.cfg.RemoveBinaryOnExit {
		if err := os.Remove(c.cniBinaryPath(c.cfg.CNIPath)); err != nil {
			return err
		}
		c.logger.Info("--remove-binary-on-exit is specified. CNI binary has been removed.", "path", c.cniBinaryPath(c.cfg.CNIPath))
	}
	return nil
}
