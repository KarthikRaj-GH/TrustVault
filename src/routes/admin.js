import { Router } from 'express';
import { writeAudit, auditDenied } from '../services/audit.js';

export function createAdminRouter({ admin, authenticate }) {
  const router = Router();
  router.use(authenticate);
  router.get('/audit', async (req, res, next) => {
    try {
      if (req.user.role !== 'administrator') {
        await auditDenied(admin, req, 'admin_audit_view');
        return res.status(403).json({ error: 'Administrator access is required.' });
      }
      const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit || '100', 10) || 100));
      let query = admin.from('audit_events')
        .select('id, actor_id, actor_role, document_id, action, outcome, ip_address, user_agent, details, created_at')
        .order('created_at', { ascending: false }).limit(limit);
      if (req.query.action) query = query.eq('action', String(req.query.action).slice(0, 80));
      if (req.query.outcome) query = query.eq('outcome', String(req.query.outcome).slice(0, 20));
      const { data, error } = await query;
      if (error) throw error;
      await writeAudit(admin, req, { action: 'admin_audit_view', outcome: 'success', details: { row_count: data?.length || 0 } });
      return res.json({ events: data || [] });
    } catch (error) { next(error); }
  });
  return router;
}
