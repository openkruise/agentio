//go:build linux && proxyinit_integration

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

package proxyinit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
)

func TestValidationReportsRepairError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.HostIP = netip.MustParseAddr("192.0.2.1")
	cfg.ProxyPort, cfg.InboundCapturePort = "0", "0"
	cfg.SkipRuleApply, cfg.RunValidation = true, true
	cfg.ProbeTimeout = 20 * time.Millisecond
	require.Same(t, ErrValidation, Run(context.Background(), cfg))
}

// Run in a subprocess so all Go runtime threads share the private netns.
func TestDNSBeforeServiceDNAT(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	if os.Getenv("AGENTIO_INIT_TEST_NETNS") != "1" {
		for _, scenario := range []struct {
			name     string
			priority string
			firewall bool
		}{
			{"service-dnat-first", "-99", false},
			{"dns-capture-first", "-101", false},
			{"earlier-firewall-with-dns-permission", "-101", true},
		} {
			t.Run(scenario.name, func(t *testing.T) {
				cmd := exec.Command("unshare", "--net", executable, "-test.run=^TestDNSBeforeServiceDNAT$", "-test.v")
				cmd.Env = append(
					os.Environ(),
					"AGENTIO_INIT_TEST_NETNS=1",
					"AGENTIO_INIT_TEST_PRIORITY="+scenario.priority,
					"AGENTIO_INIT_TEST_FIREWALL="+strconv.FormatBool(scenario.firewall),
				)
				output, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", output)
			})
		}
		return
	}
	t.Cleanup(func() {
		if t.Failed() {
			rules, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
			t.Logf("kernel rules (%v):\n%s", err, rules)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	backend := exec.CommandContext(ctx, "unshare", "--net", executable, "-test.run=^TestDNSProxyHelper$")
	backend.Env = append(os.Environ(), "AGENTIO_INIT_TEST_DNS_PROXY=1", "AGENTIO_INIT_TEST_BACKEND=1")
	startDNSProcess(t, backend)
	for _, args := range [][]string{
		{"link", "add", "proxy-veth", "type", "veth", "peer", "name", "dns-veth"},
		{"link", "set", "dns-veth", "netns", fmt.Sprint(backend.Process.Pid)},
		{"addr", "add", "10.244.0.1/24", "dev", "proxy-veth"},
		{"link", "set", "proxy-veth", "up"},
		{"route", "add", "10.96.0.10/32", "via", "10.244.0.53"},
	} {
		output, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "10.244.0.53/24", "dev", "dns-veth"},
		{"link", "set", "dns-veth", "up"},
		{"route", "add", "default", "via", "10.244.0.1"},
	} {
		command := append([]string{"--target", fmt.Sprint(backend.Process.Pid), "--net", "ip"}, args...)
		output, err := exec.Command("nsenter", command...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
	} {
		output, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	// Model both NAT orderings explicitly; equal-priority registration order is not stable.
	service := exec.Command("nft", "-f", "-")
	service.Stdin = strings.NewReader(`add table ip kube-proxy
add chain ip kube-proxy nat-output { type nat hook output priority -100; }
add rule ip kube-proxy nat-output ip daddr 10.96.0.10 udp dport 53 dnat to 10.244.0.53:53
add rule ip kube-proxy nat-output ip daddr 10.96.0.10 tcp dport 53 dnat to 10.244.0.53:53
`)
	output, err := service.CombinedOutput()
	require.NoError(t, err, "%s", output)

	priority := os.Getenv("AGENTIO_INIT_TEST_PRIORITY")
	if os.Getenv("AGENTIO_INIT_TEST_FIREWALL") == "true" {
		firewall := exec.Command("nft", "-f", "-")
		firewall.Stdin = strings.NewReader(`add table inet ztunnel
add chain inet ztunnel zt_policy_output { type filter hook output priority -150; }
add rule inet ztunnel zt_policy_output ct state established,related accept
add rule inet ztunnel zt_policy_output oifname lo accept
add rule inet ztunnel zt_policy_output meta skuid 1337 return
add rule inet ztunnel zt_policy_output udp dport 53 return
add rule inet ztunnel zt_policy_output meta l4proto != tcp reject
`)
		output, err := firewall.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	// Go's build directory can be private to root; the proxy runs as UID 1337.
	proxyDir, err := os.MkdirTemp("/tmp", "agentio-proxy-init-dns-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(proxyDir)) })
	require.NoError(t, os.Chmod(proxyDir, 0o755))
	data, err := os.ReadFile(executable)
	require.NoError(t, err)
	proxyExecutable := filepath.Join(proxyDir, "dns-proxy.test")
	require.NoError(t, os.WriteFile(proxyExecutable, data, 0o755))
	proxy := exec.CommandContext(ctx, proxyExecutable, "-test.run=^TestDNSProxyHelper$")
	proxy.Env = append(os.Environ(), "AGENTIO_INIT_TEST_DNS_PROXY=1")
	proxy.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1337, Gid: 1337}}
	startDNSProcess(t, proxy)

	args := []string{
		"-u", "1337", "-g", "1337", "-i", "*", "-b", "*",
		"--native-nftables", "--native-nftables-output-priority=" + priority, "--redirect-dns", "--capture-all-dns",
	}
	if priority != "-99" {
		args = append(args, "--reject-non-tcp")
	}
	require.NoError(t, Command(ctx, args, io.Discard, os.Stderr))
	if priority == "-99" {
		query := new(dns.Msg)
		query.SetQuestion("sandbox.example.", dns.TypeA)
		_, _, err := (&dns.Client{Timeout: time.Second}).Exchange(query, "10.96.0.10:53")
		require.Error(t, err, "Service DNAT before capture must reproduce DNS failure")
		return
	}
	for _, protocol := range []string{"udp", "tcp"} {
		query := new(dns.Msg)
		query.SetQuestion("sandbox.example.", dns.TypeA)
		response, _, err := (&dns.Client{Net: protocol, Timeout: 2 * time.Second}).Exchange(query, "10.96.0.10:53")
		require.NoError(t, err, "%s must reach the local DNS proxy and reverse NAT to the Service tuple", protocol)
		require.Len(t, response.Answer, 1)
		require.Equal(t, "192.0.2.53", response.Answer[0].(*dns.A).A.String())
		require.Equal(t, uint32(15), response.Answer[0].Header().Ttl, "DNS bypassed the local proxy")
	}

	assertNonDNSUDPRejected(t)
}

func assertNonDNSUDPRejected(t *testing.T) {
	t.Helper()
	// A real listener distinguishes REJECT from an unreachable destination.
	listener, err := net.ListenPacket("udp4", "127.0.0.1:12345")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.Dial("udp4", listener.LocalAddr().String())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	_, err = client.Write([]byte("must not bypass"))
	if err == nil {
		_, err = client.Read(make([]byte, 64))
	}
	require.Error(t, err)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, _, err = listener.ReadFrom(make([]byte, 64))
	require.Error(t, err, "non-DNS UDP reached the listener")
}

func startDNSProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", ready)
}

func TestDNSProxyHelper(t *testing.T) {
	if os.Getenv("AGENTIO_INIT_TEST_DNS_PROXY") != "1" {
		return
	}
	address := "127.0.0.1:15053"
	backend := os.Getenv("AGENTIO_INIT_TEST_BACKEND") == "1"
	if backend {
		address = "0.0.0.0:53"
	}
	udp, err := net.ListenPacket("udp4", address)
	require.NoError(t, err)
	tcp, err := net.Listen("tcp4", address)
	require.NoError(t, err)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("192.0.2.53"),
			},
		}
		if !backend {
			protocol := "udp"
			if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
				protocol = "tcp"
			}
			service := os.Getenv("DNS_TEST_SERVICE_IP")
			if service == "" {
				service = "10.96.0.10"
			}
			upstream, _, err := (&dns.Client{Net: protocol, Timeout: time.Second}).Exchange(
				request,
				net.JoinHostPort(service, "53"),
			)
			if err != nil {
				t.Errorf("upstream Service DNS failed: %v", err)
				response.SetRcode(request, dns.RcodeServerFailure)
			} else {
				response = upstream
				for _, answer := range response.Answer {
					answer.Header().Ttl = 15
				}
				fmt.Printf("forwarded DNS over %s\n", protocol)
			}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("DNS response write failed: %v", err)
		}
	})
	go func() { _ = (&dns.Server{Listener: tcp, Handler: handler}).ActivateAndServe() }()
	fmt.Println("ready")
	require.NoError(t, (&dns.Server{PacketConn: udp, Handler: handler}).ActivateAndServe())
}
