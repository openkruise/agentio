# Agentio Certificate Trust

Agentio has distinct trust relationships for business workloads and egress gateways.

## Language

**Gateway upstream trust bundle**:
The set of CA certificates an egress gateway trusts when authenticating destination services and HTTPS proxies.

**Client trust bundle**:
The set of CA certificates distributed to business workloads for authenticating services, including gateway-intercepted services when interception is enabled.

**Trust source**:
A contribution of one or more CA certificates to a trust bundle. Multiple sources can contain the same certificate.

**Agentio MITM signing CA**:
The certificate authority that issues interception certificates presented by an egress gateway to business workloads.
