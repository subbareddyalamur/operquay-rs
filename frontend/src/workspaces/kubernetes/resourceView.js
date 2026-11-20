export function editableResource(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return resource
  const { status, ...result } = resource
  if (result.metadata && typeof result.metadata === 'object') {
    const { managedFields, ...metadata } = result.metadata
    result.metadata = metadata
  }
  return result
}
