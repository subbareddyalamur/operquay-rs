export type Env = 'prod' | 'staging' | 'dev' | 'test' | 'uat' | 'qa' | 'other';

/** Production-like names. "nonprod" and "non-prod" are not production. */
export function isProdName(env: string): boolean {
  const parts = env.toLowerCase().split(/[-_\s/]+/).filter(Boolean);
  let skip = false;
  for (const p of parts) {
    if (p === 'non') {
      skip = true;
      continue;
    }
    if (skip) {
      skip = false;
      continue;
    }
    if (p === 'prod' || p === 'production' || p === 'preprod' || p === 'preproduction' || p === 'prd') {
      return true;
    }
  }
  return false;
}

/**
 * Text color for an environment label on the desk. Production is amber, the
 * same color as the session frame; red stays reserved for errors and End.
 */
export function envTone(env: string): string {
  const e = env.toLowerCase();
  if (!e) return 'text-text-dim';
  if (isProdName(e)) return 'text-warn';
  if (e.includes('val') || e.includes('uat') || e.includes('stag') || e.includes('test') || e.includes('qa')) return 'text-info';
  if (e.includes('dev') || e.includes('sandbox')) return 'text-success';
  return 'text-text-mut';
}

export function detectEnv(tags: Record<string, string>): Env {
  const t = (
    tags['Environment'] ??
    tags['environment'] ??
    tags['Env'] ??
    tags['env'] ??
    ''
  ).toLowerCase();
  if (isProdName(t)) return 'prod';
  if (t.includes('stag')) return 'staging';
  if (t.includes('dev'))  return 'dev';
  if (t.includes('test')) return 'test';
  if (t.includes('uat'))  return 'uat';
  if (t.includes('qa'))   return 'qa';
  return 'other';
}

export interface EnvRule {
  env: string;
  color: string;
  width: number;
}

/** Finds the first custom environment rule matching `env`. */
export function matchEnvRule(env: string, rules: EnvRule[] | undefined): EnvRule | undefined {
  const raw = env.trim().toLowerCase();
  if (!raw || !Array.isArray(rules)) return undefined;
  return rules.find((r) => {
    const key = r.env.trim().toLowerCase();
    if (!key) return false;
    if (key === 'prod' && isProdName(raw)) return true;
    return raw.includes(key);
  });
}

/** Preserves both the prefix and trailing suffix of long enterprise identifiers. */
export function middleTruncate(text: string, maxLen = 30): string {
  if (!text || text.length <= maxLen) return text;
  const keep = maxLen - 1;
  const head = Math.ceil(keep * 0.6);
  const tail = Math.floor(keep * 0.4);
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}
