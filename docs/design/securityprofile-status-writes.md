# SecurityProfile status writes

> Design note. This page records how `agentiod` writes the policy validation status described in [Policy validation status](../components/securityprofile-status.md). It is not required reading for operators.

One `agentiod` replica holds the `agentiod-policy-status` Lease in the control-plane namespace. A new leader replays current results. Writes use server-side apply to the status subresource with resource version and UID preconditions, preserve other condition owners, skip stale generations and suppress unchanged writes. Failed writes retry with backoff until the writer stops or a newer result replaces them. The chart grants patch permission only for these four status subresources; it does not expand Secret access.
