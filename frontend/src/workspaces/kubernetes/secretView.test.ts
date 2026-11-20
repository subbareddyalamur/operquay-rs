import { describe, expect, it } from 'vitest';
import { decodeSecret, podSecretReferences } from './secretView.js';

describe('Kubernetes secret display', () => {
  it('decodes UTF-8 and distinguishes binary, empty and invalid values', () => {
    expect(decodeSecret('aMOpbGxv')).toEqual({ text: 'héllo', kind: 'text' });
    expect(decodeSecret('AAH/')).toEqual({ text: 'AAH/', kind: 'binary' });
    expect(decodeSecret('')).toEqual({ text: '', kind: 'text' });
    expect(decodeSecret('%%%')).toEqual({ text: '', kind: 'invalid' });
  });

  it('collects only explicitly referenced Secrets and preserves key restrictions', () => {
    const refs = podSecretReferences({
      containers: [
        {
          env: [
            { valueFrom: { secretKeyRef: { name: 'env', key: 'password' } } },
            { valueFrom: { secretKeyRef: { name: 'env', key: 'user' } } },
          ],
          envFrom: [{ secretRef: { name: 'all' } }],
        },
      ],
      initContainers: [{ env: [{ valueFrom: { secretKeyRef: { name: 'env', key: 'password' } } }] }],
      ephemeralContainers: [{ envFrom: [{ secretRef: { name: 'init-secret' } }] }],
      volumes: [
        { secret: { secretName: 'volume', items: [{ key: 'cert' }] } },
        { projected: { sources: [{ secret: { name: 'projected', items: [{ key: 'token' }] } }] } },
      ],
      imagePullSecrets: [{ name: 'registry' }],
    });

    expect(refs.map((ref: { name: string; all: boolean; keys: Set<string> }) => ({ name: ref.name, all: ref.all, keys: [...ref.keys] }))).toEqual([
      { name: 'env', all: false, keys: ['password', 'user'] },
      { name: 'all', all: true, keys: [] },
      { name: 'init-secret', all: true, keys: [] },
      { name: 'volume', all: false, keys: ['cert'] },
      { name: 'projected', all: false, keys: ['token'] },
      { name: 'registry', all: true, keys: [] },
    ]);
  });

  it('merges key-specific and whole-Secret references without duplicating requests', () => {
    const refs = podSecretReferences({
      containers: [{ env: [{ valueFrom: { secretKeyRef: { name: 'shared', key: 'key' } } }], envFrom: [{ secretRef: { name: 'shared' } }] }],
    });
    expect(refs[0]?.name).toBe('shared');
    expect(refs[0]?.all).toBe(true);
    expect(podSecretReferences({ containers: [{ env: [{ valueFrom: { secretKeyRef: { name: '', key: 'key' } } }] }] })).toHaveLength(0);
  });
});
