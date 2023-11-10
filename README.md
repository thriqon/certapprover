# certapprover

[![Go](https://github.com/thriqon/certapprover/actions/workflows/go.yml/badge.svg)](https://github.com/thriqon/certapprover/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/thriqon/certapprover)](https://goreportcard.com/report/github.com/thriqon/certapprover)

[Cert-manager](https://cert-manager.io/) allows programmatic approval for `CertificateRequests` instead of automatic. This plugin uses Rego with [Open Policy Agent](https://www.openpolicyagent.org/).

## Example Policy

````rego
allow {
  input.object.metadata.namespace = "nginx-system"
}
````
