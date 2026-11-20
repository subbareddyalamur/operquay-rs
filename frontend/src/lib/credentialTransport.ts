export function canSendCredentials(path: string): boolean {
  try {
    const endpoint = new URL(`${import.meta.env.VITE_API_BASE ?? ''}${path}`, window.location.href);
    return window.location.protocol === 'https:' && endpoint.protocol === 'https:';
  } catch {
    return false;
  }
}
