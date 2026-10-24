/**
 * Central access-control decision for one document.
 * An edit grant implies read access. The route must call this on every request;
 * never trust a permission flag supplied by the browser.
 */
export function getDocumentAccess({ user, document, grant }) {
  if (!user || !document) {
    return { canRead: false, canEdit: false, canManage: false, reason: 'missing-context' };
  }
  if (user.role === 'administrator') {
    return { canRead: true, canEdit: true, canManage: true, reason: 'administrator' };
  }
  if (document.owner_id === user.id) {
    return { canRead: true, canEdit: true, canManage: true, reason: 'owner' };
  }
  const canEdit = grant?.can_edit === true;
  const canRead = grant?.can_read === true || canEdit;
  return {
    canRead,
    canEdit,
    canManage: false,
    reason: canRead ? 'explicit-grant' : 'no-grant'
  };
}

export function isRole(role) {
  return ['administrator', 'document_owner', 'viewer'].includes(role);
}
