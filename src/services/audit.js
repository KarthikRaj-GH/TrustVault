const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUuid(value) {
  return typeof value === 'string' && UUID_REGEX.test(value);
}

/**
 * Audit records are append-only at the application level. The database migration
 * also installs a trigger that rejects UPDATE and DELETE operations.
 */
export async function writeAudit(admin, req, event) {
  const isDocUuid = isValidUuid(event.documentId);
  const details = { ...(event.details ?? {}) };
  if (event.documentId && !isDocUuid) {
    details.attempted_document_id = String(event.documentId).slice(0, 160);
  }

  const row = {
    actor_id: req.user?.id ?? null,
    actor_role: req.user?.role ?? 'anonymous',
    document_id: isDocUuid ? event.documentId : null,
    action: event.action,
    outcome: event.outcome,
    ip_address: req.ip ?? null,
    user_agent: String(req.get?.('user-agent') || '').slice(0, 500),
    details
  };
  const { error } = await admin.from('audit_events').insert(row);
  if (error) {
    // Do not hide this in server logs: the judge must be able to see operational errors.
    console.error('AUDIT_WRITE_FAILED', { action: event.action, outcome: event.outcome, message: error.message });
    throw new Error('Audit logging failed; the operation could not be confirmed.');
  }
}

export async function auditDenied(admin, req, action, documentId = null) {
  try {
    await writeAudit(admin, req, { action, outcome: 'denied', documentId });
  } catch {
    // The request is still denied even if the audit store is unavailable.
  }
}
