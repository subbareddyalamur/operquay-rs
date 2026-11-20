# terraform-provider-operquay

Declarative Infrastructure-as-Code provider for managing Operquay Zero-Trust Access Control Plane resources over strict TLS (`ca_cert_path` custom root CA validation).

## Supported Resources
- `operquay_role` (`/api/roles`)
- `operquay_recording_policy` (`/api/settings/recording-policy`)
- `operquay_dlp_policy` (`/api/dlp/policy`)
- `operquay_mcp_agent` (`/api/mcp/agents`)
- `operquay_device_trust_policy` (`/api/device-trust/policy`)
- `operquay_cloud_connector` (`/api/clouds/connectors`)
- `operquay_governance_webhook` (`/api/governance/webhooks`)

## Build & Verify
```bash
cd terraform-provider-operquay
go vet ./...
go test -v ./...
go build -o terraform-provider-operquay .
./terraform-provider-operquay --describe-schema
```
