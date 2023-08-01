# certapprover

[![Go](https://github.com/thriqon/certapprover/actions/workflows/go.yml/badge.svg)](https://github.com/thriqon/certapprover/actions/workflows/go.yml)

[Cert-manager](https://cert-manager.io/) allows programmatic approval for `CertificateRequests` instead of automatic. This plugin uses Rego with [Open Policy Agent](https://www.openpolicyagent.org/).

## Example Policy

````rego
allow {
  input.object.metadata.namespace = "nginx-system"
}
````
