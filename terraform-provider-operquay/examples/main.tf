terraform {
  required_providers {
    operquay = {
      source  = "registry.terraform.io/operquay/operquay"
      version = "~> 0.1"
    }
  }
}

provider "operquay" {
  endpoint     = "https://localhost:5444"
  ca_cert_path = "../deploy/certs/operquay-local-cert.pem"
}

resource "operquay_role" "prod_db_reader" {
  name        = "prod-db-reader"
  base_role   = "user"
  description = "Read-only database viewer with PII masking enforced"
  permissions = ["db_viewer:use", "instances:read"]
}

resource "operquay_dlp_policy" "strict" {
  mask_emails = true
  mask_ssn    = true
  mask_secrets = true
}

resource "operquay_device_trust_policy" "workstation" {
  enabled                   = true
  enforce_on_desktop_launch = true
  require_disk_encryption   = true
  require_edr_running       = true
  max_os_patch_age_days     = 30
  allowed_providers         = ["crowdstrike", "jamf", "intune", "osquery"]
}

resource "operquay_mcp_agent" "claude_ops" {
  name               = "claude-ops-assistant"
  allowed_tools      = ["operquay.instances.list", "operquay.db.query"]
  require_jit_tools  = ["operquay.db.mutate"]
  rate_limit_per_min = 30
  ttl_secs           = 86400
}
