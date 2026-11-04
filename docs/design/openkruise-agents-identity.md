# OpenKruise Agents Sandbox identity derivation

> Design note. This page records how Agentio derives and validates Sandbox identity in the [OpenKruise Agents integration](../integrations/openkruise-agents.md). It is not required reading for operators.

Agentio treats the `Sandbox` as the policy subject and its backing Pod as the network endpoint and authenticated attester. The controller accepts the binding only when the Pod UID reported by the data plane matches the identity derived from the Sandbox, and the Sandbox is running with an initialized runtime.

For a non-pooled Sandbox, the fallback identity is `<namespace>--<name>`. When `agents.kruise.io/sandbox-id` is present, that label is the delivery identity. A pooled Sandbox is published as a policy subject only while it is claimed; ambiguous or stale bindings fail closed.
