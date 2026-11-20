import { expect, it } from 'vitest';
import { assistantName } from './settings';

it('names the assistant Oi unless a usable custom name is set', () => {
  expect(assistantName(undefined)).toBe('Oi');
  expect(assistantName('   ')).toBe('Oi');
  expect(assistantName('  Quay ')).toBe('Quay');
  expect(assistantName('x'.repeat(30))).toHaveLength(16);
});
