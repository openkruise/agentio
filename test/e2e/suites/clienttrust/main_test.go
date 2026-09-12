// Copyright 2026 The Kruise Authors
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

package clienttrust

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

var suite *e2e.Suite
var rig *harness.Harness
var agentioInstance agentiocomponent.Instance
var clientImage string

func TestMain(m *testing.M) {
	frameworkInputs := e2e.RegisterFlags(flag.CommandLine)
	agentioInputs := agentiocomponent.RegisterFlags(flag.CommandLine)
	flag.StringVar(&clientImage, "client-trust.image", os.Getenv("AGENTIO_E2E_CLIENT_TRUST_IMAGE"), "immutable Python/Node/curl client fixture image")
	flag.Parse()
	if os.Getenv("AGENTIO_E2E") != "1" {
		os.Exit(m.Run())
	}
	frameworkConfig, err := e2e.ResolveConfig(frameworkInputs, e2e.DefaultConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	config, err := agentiocomponent.ResolveConfig(agentioInputs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if config.Profile != agentiocomponent.ProfileSidecar {
		fmt.Fprintln(os.Stderr, "client trust tests require the sidecar profile")
		os.Exit(2)
	}
	if !regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`).MatchString(clientImage) {
		fmt.Fprintln(os.Stderr, "AGENTIO_E2E_CLIENT_TRUST_IMAGE must use repository@sha256:<64-hex-digest>")
		os.Exit(2)
	}
	config.EnableClientTrust = true
	suite = e2e.NewSuite(e2e.SuiteSpec{Name: "clienttrust"}, frameworkConfig)
	rig = harness.New(suite, config)
	for _, collector := range agentiocomponent.Collectors(config) {
		suite.RegisterCollector(collector)
	}
	suite.Setup("agentio", agentiocomponent.Setup(&agentioInstance, config))
	suite.Setup("agentio-baseline", harness.SetupBaseline(config.Namespace))
	suite.Setup("gateway-ready", func(ctx context.Context, env *e2e.Environment) (e2e.CleanupFunc, error) {
		wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		_, err := env.Kube.WaitReadyPods(wait, config.Namespace, harness.GatewayPodSelector, 1)
		return nil, err
	})
	os.Exit(suite.Run(m))
}
