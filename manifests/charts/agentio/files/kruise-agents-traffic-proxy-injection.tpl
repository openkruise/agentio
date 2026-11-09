{
  "annotations": {
    "networking.agents.kruise.io/health-probe-rewrite": {{ .Values.agentio.trafficProxy.healthProbeRewrite | toString | quote }},
    "networking.agents.kruise.io/sidecar-proxy": "traffic-proxy"
  },
  "labels": {
    "agentio.kruise.io/dataplane-mode": "none"
  },
  "initContainers": [
    {
      "args": [
        "proxy-init",
        "-p",
        "15001",
        "-z",
        "15006",
        "-u",
        "1337",
        "-m",
        "REDIRECT",
        "-i",
        {{ .Values.agentio.trafficProxy.includeOutboundIPRanges | quote }},
        "-x",
        {{ .Values.agentio.trafficProxy.excludeOutboundIPRanges | quote }},
        "-b",
        {{ .Values.agentio.trafficProxy.includeInboundPorts | quote }},
        "-d",
        {{- if .Values.agentio.trafficProxy.excludeInboundPorts }}
        {{ printf "15090,15021,15020,%s" .Values.agentio.trafficProxy.excludeInboundPorts | quote }}
        {{- else }}
        "15090,15021,15020"
        {{- end }}
        {{- if .Values.agentio.trafficProxy.includeOutboundPorts }},
        "-q",
        {{ .Values.agentio.trafficProxy.includeOutboundPorts | quote }}
        {{- end }}
        {{- if .Values.agentio.trafficProxy.excludeOutboundPorts }},
        "-o",
        {{ .Values.agentio.trafficProxy.excludeOutboundPorts | quote }}
        {{- end }},
        "--log-output-level=default:info"
      ],
      "env": [
        { "name": "AGENTIO_REDIRECT_DNS", "value": {{ .Values.agentio.trafficProxy.dnsCapture | toString | quote }} },
        { "name": "AGENTIO_NATIVE_NFTABLES", "value": {{ .Values.agentio.trafficProxy.nativeNftables | toString | quote }} },
        { "name": "AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY", "value": {{ .Values.agentio.trafficProxy.natOutputPriority | quote }} },
        { "name": "AGENTIO_REJECT_NON_TCP", "value": {{ .Values.agentio.trafficProxy.rejectNonTCP | toString | quote }} }
      ],
      "image": {{ .Values.agentio.trafficProxy.initImage | quote }},
      "imagePullPolicy": {{ .Values.agentio.trafficProxy.imagePullPolicy | quote }},
      "name": "agentio-init",
      "resources": {{ .Values.agentio.trafficProxy.initResources | toJson }},
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "capabilities": {
          "add": [
            "NET_ADMIN"
          ],
          "drop": [
            "ALL"
          ]
        },
        "privileged": false,
        "readOnlyRootFilesystem": false,
        "runAsGroup": 0,
        "runAsNonRoot": false,
        "runAsUser": 0
      }
    },
    {
      "args": [
        "proxy",
        "ztunnel"
      ],
      "env": [
        {
          "name": "ENABLE_SANDBOX_MANAGER",
          "value": {{ .Values.agentio.sandbox.enabled | toString | quote }}
        },
        {
          "name": "AGENTIO_SANDBOX_MODE",
          "value": {{ .Values.agentio.sandbox.enabled | toString | quote }}
        },
        {
          "name": "ENABLE_FIREWALL_RULES",
          "value": {{ .Values.agentio.trafficProxy.enableFirewallRules | toString | quote }}
        },
        {
          "name": "FIREWALL_BACKEND",
          "value": {{ .Values.agentio.trafficProxy.firewallBackend | quote }}
        },
        {
          "name": "ENABLE_SIDECAR_MODE",
          "value": "true"
        },
        {
          "name": "ENABLE_ORIG_SRC",
          "value": "false"
        },
        {
          "name": "PROXY_MODE",
          "value": "dedicated"
        },
        {
          "name": "XDS_ON_DEMAND",
          "value": "false"
        },
        {
          "name": "CA_ADDRESS",
          "value": {{ .Values.agentio.trafficProxy.caAddress | default (printf "%s.%s.svc.%s:15012" .Values.agentio.trafficProxy.controlPlaneService .Values.agentio.trafficProxy.controlPlaneNamespace .Values.agentio.trafficProxy.clusterDomain) | quote }}
        },
        {
          "name": "XDS_ADDRESS",
          "value": {{ .Values.agentio.trafficProxy.xdsAddress | default (printf "%s.%s.svc.%s:15012" .Values.agentio.trafficProxy.controlPlaneService .Values.agentio.trafficProxy.controlPlaneNamespace .Values.agentio.trafficProxy.clusterDomain) | quote }}
        },
        {
          "name": "RUST_BACKTRACE",
          "value": "1"
        },
        {
          "name": "ISTIO_META_CLUSTER_ID",
          "value": {{ .Values.agentio.trafficProxy.clusterId | quote }}
        },
        {
          "name": "POD_NAME",
          "valueFrom": {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "metadata.name"
            }
          }
        },
        {
          "name": "POD_NAMESPACE",
          "valueFrom": {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "metadata.namespace"
            }
          }
        },
        {
          "name": "NODE_NAME",
          "valueFrom": {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "spec.nodeName"
            }
          }
        },
        {
          "name": "INSTANCE_IP",
          "valueFrom": {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "status.podIP"
            }
          }
        },
        {
          "name": "SERVICE_ACCOUNT",
          "valueFrom": {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "spec.serviceAccountName"
            }
          }
        },
        {
          "name": "ZTUNNEL_CPU_LIMIT",
          "valueFrom": {
            "resourceFieldRef": {
              "divisor": "1",
              "resource": "limits.cpu"
            }
          }
        },
        {
          "name": "ISTIO_META_DNS_CAPTURE",
          "value": {{ .Values.agentio.trafficProxy.dnsCapture | toString | quote }}
        },
        {
          "name": "ISTIO_META_ENABLE_HBONE",
          "value": "true"
        }
      ],
      "image": {{ .Values.agentio.trafficProxy.image | quote }},
      "imagePullPolicy": {{ .Values.agentio.trafficProxy.imagePullPolicy | quote }},
      "name": "traffic-proxy",
      "ports": [
        {
          "containerPort": 15020,
          "name": "ztunnel-stats",
          "protocol": "TCP"
        }
      ],
      "readinessProbe": {
        "failureThreshold": 3,
        "httpGet": {
          "path": "/healthz/ready",
          "port": 15021,
          "scheme": "HTTP"
        },
        "periodSeconds": 10,
        "successThreshold": 1,
        "timeoutSeconds": 1
      },
      "resources": {{ .Values.agentio.trafficProxy.resources | toJson }},
      "restartPolicy": "Always",
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "capabilities": {
          "drop": [
            "ALL"
          ]
        },
        "privileged": false,
        "readOnlyRootFilesystem": true,
        "runAsGroup": 1337,
        "runAsNonRoot": true,
        "runAsUser": 1337
      },
      "volumeMounts": [
        {
          "mountPath": "/var/run/secrets/istio",
          "name": "agentio-ca-certs",
          "readOnly": true
        },
        {
          "mountPath": "/var/run/secrets/tokens",
          "name": "istio-token",
          "readOnly": true
        },
        {
          "mountPath": "/etc/podinfo",
          "name": "pod-info",
          "readOnly": true
        },
        {
          "mountPath": "/tmp",
          "name": "traffic-proxy-tmp"
        }
        {{- if .Values.agentio.sandbox.enabled }},
        {
          "mountPath": "/var/lib/ztunnel/sandbox",
          "name": "agentio-sandbox-state"
        }
        {{- end }}
      ]
    }
  ],
  "volume": [
    {
      "downwardAPI": {
        "defaultMode": 420,
        "items": [
          {
            "fieldRef": {
              "apiVersion": "v1",
              "fieldPath": "metadata.labels"
            },
            "path": "labels"
          }
        ]
      },
      "name": "pod-info"
    },
    {
      "name": "istio-token",
      "projected": {
        "defaultMode": 420,
        "sources": [
          {
            "serviceAccountToken": {
              "audience": {{ .Values.agentio.trafficProxy.tokenAudience | quote }},
              "expirationSeconds": 43200,
              "path": "istio-token"
            }
          }
        ]
      }
    },
    {
      "configMap": {
        "defaultMode": 420,
        "name": {{ .Values.agentio.trafficProxy.caCertConfigMap | quote }}
      },
      "name": "agentio-ca-certs"
    },
    {
      "emptyDir": {},
      "name": "traffic-proxy-tmp"
    }
    {{- if .Values.agentio.sandbox.enabled }},
    {
      "emptyDir": {},
      "name": "agentio-sandbox-state"
    }
    {{- end }}
  ]
}
