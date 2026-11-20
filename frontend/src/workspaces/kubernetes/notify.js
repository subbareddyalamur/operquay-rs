const listeners = new Set()

/** Shows an in-app notification, styled like the main app's toasts. */
export function notify(message, tone = 'danger') {
  const toast = { id: `${Date.now()}-${Math.random()}`, message: String(message), tone }
  listeners.forEach(listener => listener(toast))
}

export function onNotify(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}
