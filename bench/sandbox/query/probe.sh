#!/bin/sh
# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
set -eu
server=$(wget -qO- http://qstats:9001/stats)
cpu=$(awk '$1=="usage_usec" {print $2}' /sys/fs/cgroup/cpu.stat)
rss=$(awk '$1=="VmRSS:" {print $2/1024}' /proc/"$PPID"/status)
printf '{"server":%s,"client_usec":%s,"client_rss_mib":%s}\n' "$server" "$cpu" "$rss"
