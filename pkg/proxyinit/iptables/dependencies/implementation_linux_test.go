//go:build linux && proxyinit_integration

// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package dependencies

import (
	"os"
	"path/filepath"
	"testing"

	// Create a new network namespace. This will have the 'lo' interface ready but nothing else.
	_ "github.com/howardjohn/unshare-go/netns"
	// Create a new user namespace. This will map the current UID to 0.
	_ "github.com/howardjohn/unshare-go/userns"
	"github.com/vishvananda/netns"

	"github.com/stretchr/testify/require"

	testutil "github.com/openkruise/agentio/pkg/proxyinit/testutil"
)

func TestProbeCleanupMatchesUpstream(t *testing.T) {
	for _, failStage := range []string{"-A", "-D"} {
		t.Run(failStage, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "iptables-test")
			save := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'iptables v1.8.7 (nf_tables)'; fi\n"
			require.NoError(t, os.WriteFile(binary+"-save", []byte(save), 0o755))
			probe := "#!/bin/sh\nif [ \"$3\" = \"" + failStage + "\" ]; then exit 1; fi\nexit 0\n"
			require.NoError(t, os.WriteFile(binary, []byte(probe), 0o755))
			version, err := shouldUseBinaryForCurrentContext(binary)
			if failStage == "-A" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, binary, version.DetectedBinary)
			}
		})
	}
}

func TestDetectIptablesVersionStable(t *testing.T) {
	ext := &RealDependencies{}
	first, err := ext.DetectIptablesVersion(false)
	require.NoError(t, err)
	second, err := ext.DetectIptablesVersion(false)
	require.NoError(t, err)
	require.Equal(t, first.DetectedBinary, second.DetectedBinary)
}

func TestRunInSandbox(t *testing.T) {
	original := testutil.ReadFile(t, "/etc/nsswitch.conf")
	var sandboxed string

	originalNetNS, err := netns.Get()
	require.NoError(t, err)
	var sandboxedNetNS netns.NsHandle

	// Due to unshare-go imports above, this can run
	require.NoError(t, runInSandbox("", func() error {
		// We should have overwritten this file with /dev/null
		sandboxed = testutil.ReadFile(t, "/etc/nsswitch.conf")
		sandboxedNetNS, err = netns.Get()
		require.NoError(t, err)
		return nil
	}))
	after := testutil.ReadFile(t, "/etc/nsswitch.conf")
	require.Equal(t, sandboxed, "")
	require.Equal(t, original, after)
	require.Equal(t, originalNetNS.Equal(sandboxedNetNS), true)
}
