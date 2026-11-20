export interface AuthConfigResponse {
  tenant_id: string;
  required: boolean;
  local_enabled: boolean;
  local?: string;
  aws_access_mode?: string;
  sso?: { enabled: boolean; providers: SsoProviderPublic[] };
  providers?: SsoProviderPublic[];
  version?: string;
}

export interface SsoProviderPublic {
  id: string;
  tenant_id: string;
  provider_type: string;
  label: string;
  issuer: string;
  client_id: string;
  enabled: boolean;
}

export interface CurrentUserMe {
  id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: string;
  provider: string;
  groups: Array<{ id: string; name: string; source: string }>;
  permissions: string[];
}

export interface PublicUser {
  id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: string;
  provider: string;
  disabled: boolean;
  local_signin_enabled: boolean;
}

export interface PermissionInfo {
  id: string;
  category: string;
  description: string;
}

export interface RoleDef {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  base_role: string;
  is_system: boolean;
  permissions: string[];
}

export interface DetailedGroup {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  source: string;
  is_system: boolean;
  members: Array<{ user_id: string; email: string; name: string; source: string }>;
  bindings: Array<{ id: string; role_id: string; scope_type: string; scope_id: string; effect: string }>;
}

export interface IdpMapping {
  id: string;
  provider_id: string;
  external_group: string;
  group_id: string;
}

export interface ScimTokenItem {
  id: string;
  name: string;
  prefix: string;
  created_by: string;
  created_at: number;
  revoked_at: number;
}

export interface AwsAccountItem {
  id: string;
  name: string;
  access_key_id: string;
  role_arn: string;
  aws_account_id: string;
  default_region: string;
  verified: boolean;
  verified_arn: string;
}

export interface Ec2Instance {
  instance_id: string;
  name: string;
  state: string;
  instance_type: string;
  platform: string;
  private_ip: string;
  public_ip: string;
  region: string;
  availability_zone: string;
  vpc_id: string;
  subnet_id: string;
  account_id: string;
  profile: string;
  ssm_online: boolean;
}

export interface FleetStats {
  total: number;
  running: number;
  stopped: number;
  ssm_online: number;
  windows: number;
  linux: number;
  regions: number;
  vpcs: number;
}

export interface LicenseStatus {
  tenant_id: string;
  valid: boolean;
  plan: string;
  customer: string;
  max_seats: number;
  expires_at: number;
  capabilities: string[];
  raw_token_preview: string;
}

export interface K8sClusterRecord {
  id: string;
  name: string;
  source: string;
  api_server: string;
  connected: boolean;
  recording_enabled: boolean;
  region: string;
}

export interface VpcTopology {
  vpc: { id: string; cidr: string; name: string; isDefault?: boolean };
  subnets: Array<{
    id: string;
    cidr: string;
    name: string;
    az: string;
    isPublic: boolean;
    routeTableId: string;
  }>;
  instances: Array<{
    id: string;
    name: string;
    privateIp: string;
    publicIp: string;
    state: string;
    subnetId: string;
    securityGroups: string[];
  }>;
  internetGateways: Array<{ id: string; name: string }>;
  vpcPeerings: Array<{ id: string; name: string }>;
}

export async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const parsed = JSON.parse(text) as { error?: string };
      if (parsed.error) msg = parsed.error;
    } catch {
      if (text) msg = text;
    }
    throw new Error(msg);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

