import { describe, expect, it } from 'vitest';
import { clusterHosting, nodeHosting } from './cloudProvider.js';

describe('cloudProvider', () => {
  it('identifies worker providers without treating them as managed cluster services', () => {
    expect(nodeHosting([{ spec: { providerID: 'aws:///us-east-1a/i-123' } }])).toEqual({ cloud: 'aws', partial: false });
    expect(nodeHosting([{ spec: { providerID: 'azure:///subscriptions/test' } }, { spec: {} }])).toEqual({ cloud: 'azure', partial: true });
    expect(nodeHosting([{ spec: { providerID: 'gce://project/zone/vm' } }, { spec: { providerID: 'aws:///zone/i' } }])).toEqual({ cloud: 'mixed', partial: false });
    expect(nodeHosting([{ spec: { providerID: 'unknown://anything' } }])).toBeNull();
    expect(nodeHosting([{ spec: { providerID: 'aws.example.com' } }])).toBeNull();
    expect(nodeHosting([{ spec: { providerID: 'digitalocean://123' } }])).toEqual({ cloud: 'digitalocean', partial: false });
    expect(nodeHosting([{ spec: { providerID: 'hcloud://123' } }])).toEqual({ cloud: 'hetzner', partial: false });
    expect(nodeHosting([])).toBeNull();
    expect(clusterHosting({ source: 'teleport', name: 'aws-eks-looking-name' }).cloud).toBe('unknown');
    expect(clusterHosting({ source: 'kubeconfig', name: 'arn:aws:eks:us-east-1:123456789012:cluster/demo' })).toEqual({
      cloud: 'aws',
      detail: 'EKS identifier · unverified kubeconfig',
    });
    expect(clusterHosting({ source: 'kubeconfig', name: 'arn:aws:eks:bad' }).cloud).toBe('unknown');
    expect(clusterHosting({ source: 'aws' }).detail).toBe('EKS · AWS discovery');
    expect(clusterHosting({ source: 'teleport', nodeHosting: { cloud: 'gcp', partial: true } }).detail).toBe(
      'Google Cloud worker nodes · partial; control plane unknown',
    );
  });
});
