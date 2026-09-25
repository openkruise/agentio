{{- define "agentio.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" -}}
{{- end -}}

{{- define "agentio.sidecarEnabled" -}}
{{- eq .Values.profile "sidecar" -}}
{{- end -}}

{{- define "agentio.gatewayDeployerEnabled" -}}
{{- eq .Values.egressGateway.mode "gatewayAPI" -}}
{{- end -}}

{{- define "agentio.epeEnabled" -}}
{{- ne .Values.epe.mode "disabled" -}}
{{- end -}}

{{- define "agentio.epeService" -}}
{{- if eq .Values.epe.mode "managed" -}}
{{- printf "%s.%s.svc.%s" (include "epe.fullname" .) .Release.Namespace .Values.global.clusterDomain -}}
{{- else if eq .Values.epe.mode "external" -}}
{{- .Values.epe.external.address -}}
{{- end -}}
{{- end -}}

{{- define "agentio.epePort" -}}
{{- if eq .Values.epe.mode "managed" -}}
{{- .Values.epe.service.grpcPort -}}
{{- else if eq .Values.epe.mode "external" -}}
{{- .Values.epe.external.port -}}
{{- end -}}
{{- end -}}

{{- define "agentio.epeAddress" -}}
{{- if ne .Values.epe.mode "disabled" -}}
{{- printf "%s:%v" (include "agentio.epeService" .) (include "agentio.epePort" .) -}}
{{- end -}}
{{- end -}}

{{- define "agentio.validate" -}}
{{- if .Values.epe.tls.enabled -}}
{{- if eq .Values.epe.mode "managed" -}}
{{- $certificateSource := .Values.epe.tls.certificateSource | default dict -}}
{{- if and (hasKey $certificateSource "ca") (hasKey $certificateSource "file") -}}
{{- fail "epe.tls.certificateSource.ca and file are mutually exclusive" -}}
{{- end -}}
{{- range $kind, $settings := $certificateSource -}}
{{- if not (has $kind (list "ca" "file")) -}}
{{- fail "epe.tls.certificateSource must select ca or file" -}}
{{- end -}}
{{- if eq $kind "ca" -}}
{{- range $field, $value := $settings -}}
{{- if empty $value -}}
{{- fail (printf "epe.tls.certificateSource.ca.%s must not be empty when specified" $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $kind "file" -}}
{{- range $field := list "certificateFile" "privateKeyFile" "caCertificateFile" -}}
{{- if empty (index $settings $field) -}}
{{- fail (printf "epe.tls.certificateSource.file.%s is required" $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.epe.mode "external") (empty .Values.epe.tls.peerSpiffeIDs) -}}
{{- fail "epe.tls.peerSpiffeIDs is required for external mTLS" -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.egressGateway.mode "gatewayAPI") .Values.egressGateway.gatewayAPI.create -}}
{{- if empty .Values.egressGateway.gatewayAPI.name -}}
{{- fail "egressGateway.gatewayAPI.name is required when mode=gatewayAPI and create=true" -}}
{{- end -}}
{{- if empty .Values.egressGateway.gatewayAPI.gatewayClassName -}}
{{- fail "egressGateway.gatewayAPI.gatewayClassName is required when mode=gatewayAPI and create=true" -}}
{{- end -}}
{{- if empty .Values.egressGateway.gatewayAPI.listeners -}}
{{- fail "egressGateway.gatewayAPI.listeners must contain at least one listener when mode=gatewayAPI and create=true" -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.epe.mode "managed" -}}
{{- $source := .Values.epe.credentialProvider.mtls.source -}}
{{- if not (has $source (list "secret" "none")) -}}
{{- fail (printf "epe.credentialProvider.mtls.source must be secret or none; got %q" $source) -}}
{{- end -}}
{{- if and (eq $source "secret") (or (empty .Values.epe.credentialProvider.mtls.secret.namespace) (empty .Values.epe.credentialProvider.mtls.secret.name)) -}}
{{- fail "epe.credentialProvider.mtls.secret.namespace and name are required when source=secret" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "agentiod.name" -}}
{{- default "agentiod" .Values.agentiod.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentiod.fullname" -}}
{{- default (include "agentiod.name" .) .Values.agentiod.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentiod.labels" -}}
helm.sh/chart: {{ include "agentio.chart" . }}
app.kubernetes.io/name: {{ include "agentiod.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentio
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "agentiod.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentiod.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agentiod.serviceAccountName" -}}
{{- default (include "agentiod.fullname" .) .Values.agentiod.serviceAccount.name -}}
{{- end -}}

{{- define "agentiod.image" -}}
{{- if .Values.agentiod.image.digest -}}
{{- printf "%s@%s" (required "agentiod.image.repository is required when digest is set" .Values.agentiod.image.repository) .Values.agentiod.image.digest -}}
{{- else if .Values.agentiod.image.repository -}}
{{- printf "%s:%s" .Values.agentiod.image.repository (.Values.agentiod.image.tag | default .Values.global.tag) -}}
{{- else -}}
{{- printf "%s/%s:%s" .Values.global.hub .Values.agentiod.image.name (.Values.agentiod.image.tag | default .Values.global.tag) -}}
{{- end -}}
{{- end -}}

{{- define "agentiod.componentImage" -}}
{{- $image := index . 0 -}}
{{- $name := index . 1 -}}
{{- $root := index . 2 -}}
{{- if $image -}}{{ $image }}{{- else -}}{{ printf "%s/%s:%s" $root.Values.global.hub $name $root.Values.global.tag }}{{- end -}}
{{- end -}}

{{- define "agentiod.webhookName" -}}
{{- default (printf "%s-sidecar-injector-%s" (include "agentiod.fullname" .) .Release.Namespace) .Values.agentiod.injector.webhookName -}}
{{- end -}}

{{- define "agentiod.caConfigMapName" -}}
{{- default .Values.global.caCertConfigMap .Values.agentiod.ca.configMapName -}}
{{- end -}}

{{- define "agentiod.caAddress" -}}
{{- printf "%s.%s.svc.%s:15012" (include "agentiod.fullname" .) .Release.Namespace .Values.global.clusterDomain -}}
{{- end -}}

{{- define "agentio-cni.name" -}}{{ default "agentio-cni" .Values.cni.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "agentio-cni.fullname" -}}{{ default (include "agentio-cni.name" .) .Values.cni.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "agentio-cni.serviceAccountName" -}}{{ default (include "agentio-cni.fullname" .) .Values.cni.serviceAccount.name }}{{- end -}}
{{- define "agentio-cni.image" -}}
{{- if .Values.cni.image.digest }}{{ printf "%s@%s" (required "cni.image.repository is required when digest is set" .Values.cni.image.repository) .Values.cni.image.digest }}{{ else if .Values.cni.image.repository }}{{ printf "%s:%s" .Values.cni.image.repository (.Values.cni.image.tag | default .Values.global.tag) }}{{ else }}{{ printf "%s/%s:%s" .Values.global.hub .Values.cni.image.name (.Values.cni.image.tag | default .Values.global.tag) }}{{ end }}
{{- end -}}
{{- define "agentio-cni.labels" -}}
helm.sh/chart: {{ include "agentio.chart" . }}
app.kubernetes.io/name: {{ include "agentio-cni.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentio
app.kubernetes.io/component: cni
{{- end -}}
{{- define "agentio-cni.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentio-cni.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ztunnel.name" -}}{{ default "ztunnel" .Values.ztunnel.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "ztunnel.fullname" -}}{{ default (include "ztunnel.name" .) .Values.ztunnel.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "ztunnel.serviceAccountName" -}}{{ default (include "ztunnel.fullname" .) .Values.ztunnel.serviceAccount.name }}{{- end -}}
{{- define "ztunnel.image" -}}
{{- if .Values.ztunnel.image.digest }}{{ printf "%s@%s" (required "ztunnel.image.repository is required when digest is set" .Values.ztunnel.image.repository) .Values.ztunnel.image.digest }}{{ else if .Values.ztunnel.image.repository }}{{ printf "%s:%s" .Values.ztunnel.image.repository (.Values.ztunnel.image.tag | default .Values.global.tag) }}{{ else }}{{ printf "%s/%s:%s" .Values.global.hub .Values.ztunnel.image.name (.Values.ztunnel.image.tag | default .Values.global.tag) }}{{ end }}
{{- end -}}
{{- define "ztunnel.xdsAddress" -}}{{ printf "%s.%s.svc.%s:15012" (include "agentiod.fullname" .) .Release.Namespace .Values.global.clusterDomain }}{{- end -}}
{{- define "ztunnel.labels" -}}
helm.sh/chart: {{ include "agentio.chart" . }}
app.kubernetes.io/name: {{ include "ztunnel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentio
app.kubernetes.io/component: ztunnel
{{- end -}}
{{- define "ztunnel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ztunnel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "gateway.name" -}}{{ default "agentio-egress" .Values.egressGateway.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "gateway.fullname" -}}{{ default (include "gateway.name" .) .Values.egressGateway.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "gateway.serviceAccountName" -}}{{ default (include "gateway.fullname" .) .Values.egressGateway.serviceAccount.name }}{{- end -}}
{{- define "gateway.image" -}}
{{- if .Values.egressGateway.image.digest }}{{ printf "%s@%s" (required "egressGateway.image.repository is required when digest is set" .Values.egressGateway.image.repository) .Values.egressGateway.image.digest }}{{ else if .Values.egressGateway.image.repository }}{{ printf "%s:%s" .Values.egressGateway.image.repository (.Values.egressGateway.image.tag | default .Values.global.tag) }}{{ else }}{{ printf "%s/%s:%s" .Values.global.hub .Values.egressGateway.image.name (.Values.egressGateway.image.tag | default .Values.global.tag) }}{{ end }}
{{- end -}}
{{- define "gateway.xdsAddress" -}}{{ printf "%s.%s.svc.%s:15012" (include "agentiod.fullname" .) .Release.Namespace .Values.global.clusterDomain }}{{- end -}}
{{- define "gateway.epeAddress" -}}{{ include "agentio.epeAddress" . }}{{- end -}}
{{- define "gateway.labels" -}}
helm.sh/chart: {{ include "agentio.chart" . }}
app.kubernetes.io/name: {{ include "gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentio
app.kubernetes.io/component: egress-gateway
networking.agents.kruise.io/sandbox-egress: "true"
gateway.networking.k8s.io/gateway-name: {{ include "gateway.fullname" . }}
{{- end -}}
{{- define "gateway.selectorLabels" -}}
gateway.networking.k8s.io/gateway-name: {{ include "gateway.fullname" . }}
networking.agents.kruise.io/sandbox-egress: "true"
{{- end -}}

{{- define "epe.name" -}}{{ default "agentio-epe" .Values.epe.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "epe.fullname" -}}{{ default (include "epe.name" .) .Values.epe.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "epe.serviceAccountName" -}}{{ default (include "epe.fullname" .) .Values.epe.serviceAccount.name }}{{- end -}}
{{- define "epe.image" -}}
{{- if .Values.epe.image.digest }}{{ printf "%s@%s" (required "epe.image.repository is required when digest is set" .Values.epe.image.repository) .Values.epe.image.digest }}{{ else if .Values.epe.image.repository }}{{ printf "%s:%s" .Values.epe.image.repository (.Values.epe.image.tag | default .Values.global.tag) }}{{ else }}{{ printf "%s/%s:%s" .Values.global.hub .Values.epe.image.name (.Values.epe.image.tag | default .Values.global.tag) }}{{ end }}
{{- end -}}
{{- define "epe.labels" -}}
helm.sh/chart: {{ include "agentio.chart" . }}
app.kubernetes.io/name: {{ include "epe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentio
app.kubernetes.io/component: extproc
{{- end -}}
{{- define "epe.selectorLabels" -}}
app.kubernetes.io/name: {{ include "epe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
