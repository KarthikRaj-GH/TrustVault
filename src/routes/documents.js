import { Router } from 'express';
import multer from 'multer';
import { fileTypeFromBuffer } from 'file-type';
import { randomUUID } from 'node:crypto';
import { getDocumentAccess } from '../security/access.js';
import { safeDownloadName, safeSearchTerm } from '../security/filenames.js';
import { auditDenied, isValidUuid, writeAudit } from '../services/audit.js';

const uploadFields = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024, files: 1 } });
const allowedTypes = new Map([
  ['application/pdf', 'pdf'],
  ['image/png', 'png'],
  ['image/jpeg', 'jpg']
]);

async function validateUpload(file, config) {
  if (!file) return null;
  if (file.size > config.maxUploadBytes) {
    const error = new Error(`File exceeds the configured ${Math.floor(config.maxUploadBytes / 1024 / 1024)} MB limit.`);
    error.status = 413;
    throw error;
  }
  const detected = await fileTypeFromBuffer(file.buffer);
  if (!detected || !allowedTypes.has(detected.mime)) {
    const error = new Error('Unsupported file type. Upload a PDF, PNG, or JPEG image.');
    error.status = 415;
    throw error;
  }
  return { mime: detected.mime, extension: allowedTypes.get(detected.mime) };
}

async function fetchDocument(admin, id) {
  if (!isValidUuid(id)) return null;
  const { data, error } = await admin.from('documents')
    .select('id, owner_id, title, category, original_name, storage_path, content_type, size_bytes, created_at, updated_at')
    .eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}

async function permissionFor(admin, userId, documentId) {
  if (!isValidUuid(userId) || !isValidUuid(documentId)) return null;
  const { data, error } = await admin.from('document_permissions')
    .select('can_read, can_edit').eq('user_id', userId).eq('document_id', documentId).maybeSingle();
  if (error) throw error;
  return data;
}

async function accessFor(admin, req, id, action) {
  const document = await fetchDocument(admin, id);
  if (!document) {
    await auditDenied(admin, req, `document_${action}`, id);
    return { document: null, access: null };
  }
  const grant = req.user.role === 'administrator' || document.owner_id === req.user.id
    ? null : await permissionFor(admin, req.user.id, id);
  const access = getDocumentAccess({ user: req.user, document, grant });
  const allowed = action === 'read' ? access.canRead : action === 'edit' ? access.canEdit : access.canManage;
  if (!allowed) await auditDenied(admin, req, `document_${action}`, id);
  return { document, access: allowed ? access : null };
}

function publicDocument(document, access, ownerEmail = null) {
  return {
    id: document.id,
    owner_id: document.owner_id,
    owner_email: ownerEmail,
    title: document.title,
    category: document.category,
    original_name: document.original_name,
    content_type: document.content_type,
    size_bytes: document.size_bytes,
    created_at: document.created_at,
    updated_at: document.updated_at,
    can_read: Boolean(access?.canRead),
    can_edit: Boolean(access?.canEdit),
    can_manage: Boolean(access?.canManage)
  };
}

export function createDocumentsRouter({ admin, authenticate, config }) {
  const router = Router();
  router.use(authenticate);

  router.get('/', async (req, res, next) => {
    try {
      const q = safeSearchTerm(req.query.q || '');
      const category = safeSearchTerm(req.query.category || '');
      let ids = null;
      if (req.user.role !== 'administrator') {
        const { data: grants, error: grantError } = await admin.from('document_permissions')
          .select('document_id, can_read, can_edit').eq('user_id', req.user.id);
        if (grantError) throw grantError;
        const readableGrantIds = (grants || []).filter(g => g.can_read || g.can_edit).map(g => g.document_id);
        const { data: owned, error: ownedError } = await admin.from('documents').select('id').eq('owner_id', req.user.id);
        if (ownedError) throw ownedError;
        ids = [...new Set([...readableGrantIds, ...(owned || []).map(d => d.id)])];
        if (!ids.length) return res.json({ documents: [] });
      }

      let query = admin.from('documents')
        .select('id, owner_id, title, category, original_name, content_type, size_bytes, created_at, updated_at')
        .order('created_at', { ascending: false }).limit(200);
      if (ids) query = query.in('id', ids);
      if (q) query = query.ilike('title', `%${q}%`);
      if (category) query = query.eq('category', category);
      if (req.query.from) query = query.gte('created_at', String(req.query.from).slice(0, 10));
      if (req.query.to) query = query.lte('created_at', `${String(req.query.to).slice(0, 10)}T23:59:59.999Z`);
      const { data: documents, error } = await query;
      if (error) throw error;

      const idsInList = (documents || []).map(d => d.id);
      const grantsRes = idsInList.length && req.user.role !== 'administrator'
        ? await admin.from('document_permissions').select('document_id, can_read, can_edit').eq('user_id', req.user.id).in('document_id', idsInList)
        : { data: [] };
      if (grantsRes.error) throw grantsRes.error;
      const grantMap = new Map((grantsRes.data || []).map(g => [g.document_id, g]));
      const ownerIds = [...new Set((documents || []).map(d => d.owner_id))];
      const profileRes = ownerIds.length ? await admin.from('profiles').select('id, email').in('id', ownerIds) : { data: [] };
      if (profileRes.error) throw profileRes.error;
      const ownerMap = new Map((profileRes.data || []).map(p => [p.id, p.email]));
      const safeDocs = (documents || []).map(doc => {
        const grant = req.user.role === 'administrator' || doc.owner_id === req.user.id ? null : grantMap.get(doc.id);
        const access = getDocumentAccess({ user: req.user, document: doc, grant });
        return publicDocument(doc, access, ownerMap.get(doc.owner_id) || null);
      });
      return res.json({ documents: safeDocs });
    } catch (error) { next(error); }
  });

  router.post('/', uploadFields.single('file'), async (req, res, next) => {
    let storagePath = null;
    try {
      if (req.user.role === 'viewer') {
        await auditDenied(admin, req, 'document_upload');
        return res.status(403).json({ error: 'Viewers cannot upload documents.' });
      }
      const file = req.file;
      if (!file) return res.status(400).json({ error: 'Choose a PDF, PNG, or JPEG file.' });
      const validated = await validateUpload(file, config);
      const title = String(req.body.title || file.originalname).trim().slice(0, 160);
      const category = String(req.body.category || 'General').trim().slice(0, 80);
      if (!title) return res.status(400).json({ error: 'A document title is required.' });
      storagePath = `${req.user.id}/${randomUUID()}.${validated.extension}`;
      await writeAudit(admin, req, { action: 'document_upload', outcome: 'attempt', details: { title, category, content_type: validated.mime, size_bytes: file.size } });
      const { error: storageError } = await admin.storage.from(config.bucket).upload(storagePath, file.buffer, {
        contentType: validated.mime, upsert: false
      });
      if (storageError) throw storageError;
      const { data: document, error: dbError } = await admin.from('documents').insert({
        owner_id: req.user.id,
        title,
        category: category || 'General',
        original_name: safeDownloadName(file.originalname),
        storage_path: storagePath,
        content_type: validated.mime,
        size_bytes: file.size
      }).select('id, owner_id, title, category, original_name, content_type, size_bytes, created_at, updated_at').single();
      if (dbError) {
        await admin.storage.from(config.bucket).remove([storagePath]);
        throw dbError;
      }
      await writeAudit(admin, req, { action: 'document_upload', outcome: 'success', documentId: document.id, details: { title, category, content_type: validated.mime, size_bytes: file.size } });
      return res.status(201).json({ document: publicDocument(document, { canRead: true, canEdit: true, canManage: true }) });
    } catch (error) {
      if (storagePath) await admin.storage.from(config.bucket).remove([storagePath]).catch(() => {});
      next(error);
    }
  });

  router.get('/:id', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'read');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'You do not have access to this document.' });
      await writeAudit(admin, req, { action: 'document_view', outcome: 'success', documentId: document.id });
      return res.json({ document: publicDocument(document, access) });
    } catch (error) { next(error); }
  });

  router.get('/:id/download', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'read');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'You do not have access to download this document.' });
      const { data: blob, error } = await admin.storage.from(config.bucket).download(document.storage_path);
      if (error || !blob) throw error || new Error('Stored file was not found.');
      const buffer = Buffer.from(await blob.arrayBuffer());
      await writeAudit(admin, req, { action: 'document_download', outcome: 'success', documentId: document.id, details: { size_bytes: buffer.length } });
      res.setHeader('Content-Type', document.content_type);
      res.setHeader('Content-Length', String(buffer.length));
      res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName(document.original_name)}"`);
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.status(200).send(buffer);
    } catch (error) { next(error); }
  });

  router.patch('/:id', uploadFields.single('file'), async (req, res, next) => {
    let newStoragePath = null;
    let dbUpdated = false;
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'edit');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'You do not have permission to edit this document.' });
      const updates = {};
      if (req.body.title !== undefined) {
        const title = String(req.body.title).trim().slice(0, 160);
        if (!title) return res.status(400).json({ error: 'Title cannot be empty.' });
        updates.title = title;
      }
      if (req.body.category !== undefined) updates.category = String(req.body.category).trim().slice(0, 80) || 'General';
      let oldPath = null;
      if (req.file) {
        const validated = await validateUpload(req.file, config);
        newStoragePath = `${document.owner_id}/${randomUUID()}.${validated.extension}`;
        const { error: storageError } = await admin.storage.from(config.bucket).upload(newStoragePath, req.file.buffer, { contentType: validated.mime, upsert: false });
        if (storageError) throw storageError;
        updates.storage_path = newStoragePath;
        updates.original_name = safeDownloadName(req.file.originalname);
        updates.content_type = validated.mime;
        updates.size_bytes = req.file.size;
        oldPath = document.storage_path;
      }
      if (!Object.keys(updates).length) return res.status(400).json({ error: 'Provide a title, category, or replacement file.' });
      await writeAudit(admin, req, { action: 'document_edit', outcome: 'attempt', documentId: document.id, details: { changed_fields: Object.keys(updates) } });
      const { data: updated, error } = await admin.from('documents').update(updates).eq('id', document.id)
        .select('id, owner_id, title, category, original_name, content_type, size_bytes, created_at, updated_at').single();
      if (error) throw error;
      dbUpdated = true;
      if (oldPath) {
        const { error: removeError } = await admin.storage.from(config.bucket).remove([oldPath]);
        if (removeError) console.error('OLD_FILE_CLEANUP_FAILED', { documentId: document.id, message: removeError.message });
      }
      await writeAudit(admin, req, { action: 'document_edit', outcome: 'success', documentId: document.id, details: { changed_fields: Object.keys(updates) } });
      return res.json({ document: publicDocument(updated, access) });
    } catch (error) {
      if (newStoragePath && !dbUpdated) await admin.storage.from(config.bucket).remove([newStoragePath]).catch(() => {});
      next(error);
    }
  });

  router.delete('/:id', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'manage');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'Only the owner or administrator can delete this document.' });
      await writeAudit(admin, req, { action: 'document_delete', outcome: 'attempt', documentId: document.id, details: { title: document.title } });
      const { error: deleteError } = await admin.from('documents').delete().eq('id', document.id);
      if (deleteError) throw deleteError;
      const { error: storageError } = await admin.storage.from(config.bucket).remove([document.storage_path]);
      if (storageError) {
        console.error('STORAGE_DELETE_FAILED', { documentId: document.id, path: document.storage_path, message: storageError.message });
      }
      await writeAudit(admin, req, { action: 'document_delete', outcome: 'success', documentId: document.id, details: { title: document.title } });
      return res.status(204).end();
    } catch (error) { next(error); }
  });

  router.get('/:id/permissions', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'manage');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'Only the owner or administrator can manage permissions.' });
      const { data, error } = await admin.from('document_permissions')
        .select('user_id, can_read, can_edit, created_at').eq('document_id', document.id).order('created_at', { ascending: false });
      if (error) throw error;
      const userIds = [...new Set((data || []).map(p => p.user_id))];
      const profiles = userIds.length ? await admin.from('profiles').select('id, email, full_name').in('id', userIds) : { data: [], error: null };
      if (profiles.error) throw profiles.error;
      const map = new Map((profiles.data || []).map(p => [p.id, p]));
      return res.json({ permissions: (data || []).map(p => ({ ...p, email: map.get(p.user_id)?.email || null, full_name: map.get(p.user_id)?.full_name || null })) });
    } catch (error) { next(error); }
  });

  router.post('/:id/permissions', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'manage');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'Only the owner or administrator can grant access.' });
      const email = String(req.body?.email || '').trim().toLowerCase();
      const canRead = req.body?.can_read === true;
      const canEdit = req.body?.can_edit === true;
      if (!email || email.length > 254 || (!canRead && !canEdit)) {
        return res.status(400).json({ error: 'Provide a valid account email and at least read or edit access.' });
      }
      const { data: profile, error: profileError } = await admin.from('profiles').select('id, email').eq('email', email).maybeSingle();
      if (profileError) throw profileError;
      if (!profile) return res.status(404).json({ error: 'No provisioned TrustVault user has that email.' });
      if (profile.id === document.owner_id) return res.status(400).json({ error: 'The owner already has full access.' });
      await writeAudit(admin, req, { action: 'permission_grant', outcome: 'attempt', documentId: document.id, details: { target_user_id: profile.id, can_read: canRead || canEdit, can_edit: canEdit } });
      const { data, error } = await admin.from('document_permissions').upsert({
        document_id: document.id, user_id: profile.id, can_read: canRead || canEdit, can_edit: canEdit, created_by: req.user.id
      }, { onConflict: 'document_id,user_id' }).select('document_id, user_id, can_read, can_edit, created_at').single();
      if (error) throw error;
      await writeAudit(admin, req, { action: 'permission_grant', outcome: 'success', documentId: document.id, details: { target_user_id: profile.id, can_read: canRead || canEdit, can_edit: canEdit } });
      return res.status(201).json({ permission: { ...data, email: profile.email } });
    } catch (error) { next(error); }
  });

  router.delete('/:id/permissions/:userId', async (req, res, next) => {
    try {
      const { document, access } = await accessFor(admin, req, req.params.id, 'manage');
      if (!document) return res.status(404).json({ error: 'Document not found.' });
      if (!access) return res.status(403).json({ error: 'Only the owner or administrator can revoke access.' });
      if (!isValidUuid(req.params.userId)) return res.status(400).json({ error: 'Invalid user ID format.' });
      await writeAudit(admin, req, { action: 'permission_revoke', outcome: 'attempt', documentId: document.id, details: { target_user_id: req.params.userId } });
      const { error } = await admin.from('document_permissions').delete().eq('document_id', document.id).eq('user_id', req.params.userId);
      if (error) throw error;
      await writeAudit(admin, req, { action: 'permission_revoke', outcome: 'success', documentId: document.id, details: { target_user_id: req.params.userId } });
      return res.status(204).end();
    } catch (error) { next(error); }
  });

  return router;
}
