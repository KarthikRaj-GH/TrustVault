import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createMockSupabase } from './mockSupabase.js';

const VALID_PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF');
const VALID_PNG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
const INVALID_TXT = Buffer.from('This is a plain text file, not a pdf.');

const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const VIEWER_ID = '22222222-2222-4222-8222-222222222222';
const ADMIN_ID = '33333333-3333-4333-8333-333333333333';
const DOC_ID = '44444444-4444-4444-8444-444444444444';

function setupTestEnv() {
  const mock = createMockSupabase({
    profiles: [
      { id: OWNER_ID, email: 'owner@example.com', full_name: 'Document Owner', role: 'document_owner', token: 'token-owner', password: 'Pass123!Owner' },
      { id: VIEWER_ID, email: 'viewer@example.com', full_name: 'Document Viewer', role: 'viewer', token: 'token-viewer', password: 'Pass123!Viewer' },
      { id: ADMIN_ID, email: 'admin@example.com', full_name: 'Security Admin', role: 'administrator', token: 'token-admin', password: 'Pass123!Admin' }
    ],
    documents: [
      {
        id: DOC_ID,
        owner_id: OWNER_ID,
        title: 'Confidential Financial Plan',
        category: 'Finance',
        original_name: 'financials.pdf',
        storage_path: `${OWNER_ID}/finance.pdf`,
        content_type: 'application/pdf',
        size_bytes: VALID_PDF.length,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ],
    storage: [
      {
        path: `${OWNER_ID}/finance.pdf`,
        buffer: VALID_PDF,
        contentType: 'application/pdf'
      }
    ]
  });

  const config = {
    nodeEnv: 'test',
    isProduction: false,
    port: 3000,
    appOrigin: 'http://localhost:3000',
    supabaseUrl: 'https://test.supabase.co',
    supabaseAnonKey: 'anon-test',
    supabaseServiceRoleKey: 'service-test',
    bucket: 'trustvault-private',
    maxUploadBytes: 10 * 1024 * 1024
  };

  const app = createApp({ admin: mock.admin, createPublicClient: mock.createPublicClient, config });
  return { app, mock, config };
}

describe('TrustVault Security Integration Tests', () => {
  describe('Authentication & Direct API Requests', () => {
    it('rejects direct unauthenticated API requests with 401', async () => {
      const { app } = setupTestEnv();
      const res = await request(app).get('/api/documents');
      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/sign in/i);
    });

    it('returns provisioned user profile on valid session', async () => {
      const { app } = setupTestEnv();
      const res = await request(app)
        .get('/api/auth/me')
        .set('Cookie', ['tv_access=token-owner']);
      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({
        id: OWNER_ID,
        email: 'owner@example.com',
        role: 'document_owner'
      });
      expect(res.body.user.full_name).toBe('Document Owner');
    });
  });

  describe('Server-Side Authorization & Anti-IDOR (Guessed Document IDs)', () => {
    it('denies a viewer trying to read another user document with 403 (unauthorized document access)', async () => {
      const { app, mock } = setupTestEnv();
      const res = await request(app)
        .get(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer']);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/do not have access/i);

      // Verify audit log captured the denial
      const deniedEvent = mock.tables.auditEvents.find(e => e.action === 'document_read' && e.outcome === 'denied');
      expect(deniedEvent).toBeDefined();
      expect(deniedEvent.actor_id).toBe(VIEWER_ID);
      expect(deniedEvent.document_id).toBe(DOC_ID);
    });

    it('safely handles malformed non-UUID guessed document IDs with 404 and logs the probe', async () => {
      const { app, mock } = setupTestEnv();
      const malformedId = 'guessed_admin_secret_doc';
      const res = await request(app)
        .get(`/api/documents/${malformedId}`)
        .set('Cookie', ['tv_access=token-viewer']);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Document not found.');

      // Check probe recorded in audit log without database crash
      const deniedEvent = mock.tables.auditEvents.find(e => e.action === 'document_read');
      expect(deniedEvent).toBeDefined();
      expect(deniedEvent.document_id).toBeNull();
      expect(deniedEvent.details.attempted_document_id).toBe(malformedId);
    });

    it('returns 404 for non-existent valid UUID and captures denial', async () => {
      const { app, mock } = setupTestEnv();
      const randomUuid = '99999999-9999-4999-8999-999999999999';
      const res = await request(app)
        .get(`/api/documents/${randomUuid}`)
        .set('Cookie', ['tv_access=token-viewer']);

      expect(res.status).toBe(404);
      const deniedEvent = mock.tables.auditEvents.find(e => e.action === 'document_read' && e.document_id === randomUuid);
      expect(deniedEvent).toBeDefined();
    });
  });

  describe('Direct Route Bypass & Privilege Restrictions', () => {
    it('denies viewer direct API request to edit an unshared document', async () => {
      const { app } = setupTestEnv();
      const res = await request(app)
        .patch(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer'])
        .send({ title: 'Hacked Title' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission to edit/i);
    });

    it('denies viewer direct API request to delete an unshared document', async () => {
      const { app } = setupTestEnv();
      const res = await request(app)
        .delete(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer']);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/owner or administrator/i);
    });

    it('denies viewer direct API request to view or grant permissions', async () => {
      const { app } = setupTestEnv();
      const viewRes = await request(app)
        .get(`/api/documents/${DOC_ID}/permissions`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(viewRes.status).toBe(403);

      const grantRes = await request(app)
        .post(`/api/documents/${DOC_ID}/permissions`)
        .set('Cookie', ['tv_access=token-viewer'])
        .send({ email: 'admin@example.com', can_read: true });
      expect(grantRes.status).toBe(403);
    });

    it('denies viewer from uploading documents and audits the denial', async () => {
      const { app, mock } = setupTestEnv();
      const res = await request(app)
        .post('/api/documents')
        .set('Cookie', ['tv_access=token-viewer'])
        .field('title', 'Unauthorized Viewer Upload')
        .attach('file', VALID_PDF, 'test.pdf');

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Viewers cannot upload documents.');

      const audit = mock.tables.auditEvents.find(e => e.action === 'document_upload' && e.outcome === 'denied');
      expect(audit).toBeDefined();
      expect(audit.actor_id).toBe(VIEWER_ID);
    });

    it('denies non-admin accounts from viewing admin audit logs', async () => {
      const { app, mock } = setupTestEnv();
      const res = await request(app)
        .get('/api/admin/audit')
        .set('Cookie', ['tv_access=token-owner']);

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Administrator access is required.');

      const denialAudit = mock.tables.auditEvents.find(e => e.action === 'admin_audit_view' && e.outcome === 'denied');
      expect(denialAudit).toBeDefined();
      expect(denialAudit.actor_id).toBe(OWNER_ID);
    });
  });

  describe('Per-Document Access Grants & Immediate Permission Revocation', () => {
    it('verifies the full lifecycle: unauthorized -> granted read -> download -> revoked -> immediate denial', async () => {
      const { app, mock } = setupTestEnv();

      // Step 1: Viewer tries to download before grant -> 403
      const preDownload = await request(app)
        .get(`/api/documents/${DOC_ID}/download`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(preDownload.status).toBe(403);

      // Step 2: Owner grants read access to viewer
      const grantRes = await request(app)
        .post(`/api/documents/${DOC_ID}/permissions`)
        .set('Cookie', ['tv_access=token-owner'])
        .send({ email: 'viewer@example.com', can_read: true, can_edit: false });
      expect(grantRes.status).toBe(201);
      expect(grantRes.body.permission.can_read).toBe(true);

      // Step 3: Viewer can now download with private storage headers
      const downloadRes = await request(app)
        .get(`/api/documents/${DOC_ID}/download`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(downloadRes.status).toBe(200);
      expect(downloadRes.headers['content-disposition']).toContain('attachment; filename="financials.pdf"');
      expect(downloadRes.headers['cache-control']).toBe('private, no-store');
      expect(downloadRes.headers['x-content-type-options']).toBe('nosniff');

      // Viewer cannot edit with read-only grant
      const editAttempt = await request(app)
        .patch(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer'])
        .send({ title: 'Viewer Attempting Edit' });
      expect(editAttempt.status).toBe(403);

      // Step 4: Owner immediately revokes access
      const revokeRes = await request(app)
        .delete(`/api/documents/${DOC_ID}/permissions/${VIEWER_ID}`)
        .set('Cookie', ['tv_access=token-owner']);
      expect(revokeRes.status).toBe(204);

      // Step 5: Immediate next download request by viewer is rejected with 403
      const postRevokeDownload = await request(app)
        .get(`/api/documents/${DOC_ID}/download`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(postRevokeDownload.status).toBe(403);
      expect(postRevokeDownload.body.error).toMatch(/do not have access/i);
    });

    it('verifies edit grant implies read access and allows metadata edits but not deletion', async () => {
      const { app } = setupTestEnv();

      // Grant edit access to viewer
      const grantRes = await request(app)
        .post(`/api/documents/${DOC_ID}/permissions`)
        .set('Cookie', ['tv_access=token-owner'])
        .send({ email: 'viewer@example.com', can_edit: true });
      expect(grantRes.status).toBe(201);
      expect(grantRes.body.permission.can_edit).toBe(true);
      expect(grantRes.body.permission.can_read).toBe(true);

      // Viewer can download because edit implies read
      const downloadRes = await request(app)
        .get(`/api/documents/${DOC_ID}/download`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(downloadRes.status).toBe(200);

      // Viewer can edit document title
      const editRes = await request(app)
        .patch(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer'])
        .send({ title: 'Updated Financial Plan' });
      expect(editRes.status).toBe(200);
      expect(editRes.body.document.title).toBe('Updated Financial Plan');

      // Viewer cannot delete even with edit grant
      const deleteRes = await request(app)
        .delete(`/api/documents/${DOC_ID}`)
        .set('Cookie', ['tv_access=token-viewer']);
      expect(deleteRes.status).toBe(403);
    });
  });

  describe('File Upload Validation & Security Controls', () => {
    it('rejects unsupported file MIME type (text file instead of PDF/image) with 415', async () => {
      const { app } = setupTestEnv();
      const res = await request(app)
        .post('/api/documents')
        .set('Cookie', ['tv_access=token-owner'])
        .field('title', 'Fake PDF')
        .attach('file', INVALID_TXT, 'fake.pdf');

      expect(res.status).toBe(415);
      expect(res.body.error).toMatch(/unsupported file type/i);
    });

    it('accepts valid PNG image upload by document owner', async () => {
      const { app } = setupTestEnv();
      const res = await request(app)
        .post('/api/documents')
        .set('Cookie', ['tv_access=token-owner'])
        .field('title', 'Company Logo')
        .field('category', 'Branding')
        .attach('file', VALID_PNG, 'logo.png');

      expect(res.status).toBe(201);
      expect(res.body.document.title).toBe('Company Logo');
      expect(res.body.document.content_type).toBe('image/png');
    });
  });

  describe('Administrative Oversight & Audit Trails', () => {
    it('allows administrator to view recent audit events', async () => {
      const { app, mock } = setupTestEnv();
      const res = await request(app)
        .get('/api/admin/audit')
        .set('Cookie', ['tv_access=token-admin']);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.events)).toBe(true);

      const adminViewAudit = mock.tables.auditEvents.find(e => e.action === 'admin_audit_view' && e.outcome === 'success');
      expect(adminViewAudit).toBeDefined();
      expect(adminViewAudit.actor_role).toBe('administrator');
    });
  });
});
