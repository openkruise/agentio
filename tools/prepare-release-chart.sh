#!/usr/bin/env bash

# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

chart_dir="${1:-}"
version="${2:-}"
agentiod_image="${3:-}"
epe_image="${4:-}"
ztunnel_image="${5:-}"
cni_image="${6:-}"
proxy_init_image="${7:-}"
gateway_image="${8:-}"
porter_image="${9:-}"
if [[ -z "${chart_dir}" || ! -f "${chart_dir}/Chart.yaml" || ! -f "${chart_dir}/values.yaml" ]]; then
  echo "usage: $0 <chart-directory> <semantic-version> <agentiod-image> <epe-image> <ztunnel-image> <cni-image> <proxy-init-image> <gateway-image> <porter-image>" >&2
  exit 2
fi
semver_core='(0|[1-9][0-9]*)'
semver_identifier='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
semver_pattern="^${semver_core}\\.${semver_core}\\.${semver_core}(-${semver_identifier}(\\.${semver_identifier})*)?$"
if [[ ! "${version}" =~ ${semver_pattern} ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi
image_pattern='^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$'
images=("${agentiod_image}" "${epe_image}" "${ztunnel_image}" "${cni_image}" "${proxy_init_image}" "${gateway_image}" "${porter_image}")
image_names=(agentiod epe ztunnel cni proxy-init gateway porter)
for index in "${!images[@]}"; do
  if [[ ! "${images[$index]}" =~ ${image_pattern} ]]; then
    echo "invalid immutable ${image_names[$index]} image: ${images[$index]}" >&2
    exit 2
  fi
done

agentiod_repository="${agentiod_image%@*}"
agentiod_digest="${agentiod_image##*@}"
epe_repository="${epe_image%@*}"
epe_digest="${epe_image##*@}"
ztunnel_repository="${ztunnel_image%@*}"
ztunnel_digest="${ztunnel_image##*@}"
cni_repository="${cni_image%@*}"
cni_digest="${cni_image##*@}"
gateway_repository="${gateway_image%@*}"
gateway_digest="${gateway_image##*@}"
porter_repository="${porter_image%@*}"
porter_digest="${porter_image##*@}"

sed -i.bak \
  -e "s/^version: .*/version: \"${version}\"/" \
  -e "s/^appVersion: .*/appVersion: \"${version}\"/" \
  "${chart_dir}/Chart.yaml"
sed -i.bak \
		-e "/^global:/,/^[^[:space:]]/ s/^  tag: .*$/  tag: \"${version}\"/" \
		-e "/^agentiod:/,/^[^[:space:]]/ s|^    repository:.*$|    repository: \"${agentiod_repository}\"|" \
		-e "/^agentiod:/,/^[^[:space:]]/ s/^    tag: .*$/    tag: \"\"/" \
		-e "/^agentiod:/,/^[^[:space:]]/ s|^    digest:.*$|    digest: \"${agentiod_digest}\"|" \
		-e "/^    ztunnel:/,/^    proxyInit:/ s|^      image:.*$|      image: \"${ztunnel_image}\"|" \
	-e "/^    proxyInit:/,/^  gatewayDeployer:/ s|^      image:.*$|      image: \"${proxy_init_image}\"|" \
	-e "/^cni:/,/^ztunnel:/ s|^    repository:.*$|    repository: \"${cni_repository}\"|" \
	-e "/^cni:/,/^ztunnel:/ s/^    tag: .*$/    tag: \"\"/" \
	-e "/^cni:/,/^ztunnel:/ s|^    digest:.*$|    digest: \"${cni_digest}\"|" \
	-e "/^ztunnel:/,/^egressGateway:/ s|^    repository:.*$|    repository: \"${ztunnel_repository}\"|" \
	-e "/^ztunnel:/,/^egressGateway:/ s/^    tag: .*$/    tag: \"\"/" \
	-e "/^ztunnel:/,/^egressGateway:/ s|^    digest:.*$|    digest: \"${ztunnel_digest}\"|" \
		-e "/^egressGateway:/,/^epe:/ s|^    repository:.*$|    repository: \"${gateway_repository}\"|" \
		-e "/^egressGateway:/,/^epe:/ s/^    tag: .*$/    tag: \"\"/" \
		-e "/^egressGateway:/,/^epe:/ s|^    digest:.*$|    digest: \"${gateway_digest}\"|" \
		-e "/^  porter:/,/^  [^[:space:]]/ s|^      repository:.*$|      repository: \"${porter_repository}\"|" \
		-e "/^  porter:/,/^  [^[:space:]]/ s/^      tag: .*$/      tag: \"\"/" \
		-e "/^  porter:/,/^  [^[:space:]]/ s|^      digest:.*$|      digest: \"${porter_digest}\"|" \
		-e "/^epe:/,$ s|^    repository:.*$|    repository: \"${epe_repository}\"|" \
		-e "/^epe:/,$ s/^    tag: .*$/    tag: \"\"/" \
		-e "/^epe:/,$ s|^    digest:.*$|    digest: \"${epe_digest}\"|" \
		"${chart_dir}/values.yaml"
rm -f "${chart_dir}/Chart.yaml.bak" "${chart_dir}/values.yaml.bak"

# Build the embedded integrations only after all release images are pinned.
repo_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
chart_dir=$(CDPATH= cd -- "$chart_dir" && pwd)
(
  cd "$repo_dir"
  go run ./tools/agentio-chart-sync build --chart "$chart_dir"
  go run ./tools/agentio-chart-sync verify --bundle "$chart_dir/integrations/openkruise"
)
