import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDocumentAccess, isRole } from '../src/security/access.js';
import { safeDownloadName, safeSearchTerm } from '../src/security/filenames.js';
import { isValidUuid } from '../src/services/audit.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const document = { id: 'doc-1', owner_id: 'owner-1' };

describe('document authorization decisions', () => {
  it('denies a viewer with no grant', () => {
    const access = getDocumentAccess({ user: { id: 'viewer-1', role: 'viewer' }, document, grant: null });
    expect(access.canRead).toBe(false);
    expect(access.canEdit).toBe(false);
    expect(access.canManage).toBe(false);
  });

  it('allows a named read grant without granting edit or management', () => {
    const access = getDocumentAccess({
      user: { id: 'viewer-1', role: 'viewer' }, document,
      grant: { can_read: true, can_edit: false }
    });
    expect(access).toMatchObject({ canRead: true, canEdit: false, canManage: false });
  });

  it('treats an edit grant as read plus edit, but not permission management', () => {
    const access = getDocumentAccess({
      user: { id: 'editor-1', role: 'viewer' }, document,
      grant: { can_read: false, can_edit: true }
    });
    expect(access).toMatchObject({ canRead: true, canEdit: true, canManage: false });
  });

  it('gives the owner document-management access', () => {
    const access = getDocumentAccess({ user: { id: 'owner-1', role: 'document_owner' }, document, grant: null });
    expect(access).toMatchObject({ canRead: true, canEdit: true, canManage: true });
  });

  it('gives the explicitly privileged administrator full access', () => {
    const access = getDocumentAccess({ user: { id: 'admin-1', role: 'administrator' }, document, grant: null });
    expect(access).toMatchObject({ canRead: true, canEdit: true, canManage: true });
  });

  it('does not grant access when the user context or document is missing', () => {
    expect(getDocumentAccess({ user: null, document, grant: null }).canRead).toBe(false);
    expect(getDocumentAccess({ user: { id: 'viewer-1', role: 'viewer' }, document: null, grant: null }).canRead).toBe(false);
  });

  it('accepts only the three documented roles', () => {
    expect(isRole('administrator')).toBe(true);
    expect(isRole('document_owner')).toBe(true);
    expect(isRole('viewer')).toBe(true);
    expect(isRole('superuser')).toBe(false);
  });
});

describe('input safety helpers', () => {
  it('removes path separators, control characters and quote characters from download names', () => {
    expect(safeDownloadName('../secret\\\"\r\n.pdf')).toBe('.._secret__.pdf');
    expect(safeDownloadName('')).toBe('document');
  });

  it('limits search input length and neutralizes PostgREST wildcard punctuation', () => {
    expect(safeSearchTerm('report%_final')).toBe('report _final');
    expect(safeSearchTerm('x'.repeat(200))).toHaveLength(100);
  });

  it('validates UUID format strictly', () => {
    expect(isValidUuid('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
    expect(isValidUuid('not-a-uuid')).toBe(false);
    expect(isValidUuid('../secret')).toBe(false);
    expect(isValidUuid(null)).toBe(false);
    expect(isValidUuid('')).toBe(false);
  });
});

describe('client-side script safety checks', () => {
  it('does not reference event.currentTarget after an await in public/app.js', () => {
    const appJs = fs.readFileSync(path.resolve(here, '../public/app.js'), 'utf-8');
    const asyncHandlers = appJs.split(/addEventListener\s*\(\s*['"][^'"]+['"]\s*,\s*async\s*\([^)]*\)\s*=>\s*\{/);
    for (let i = 1; i < asyncHandlers.length; i++) {
      const block = asyncHandlers[i];
      const awaitIndex = block.indexOf('await ');
      if (awaitIndex !== -1) {
        const afterAwait = block.slice(awaitIndex);
        expect(afterAwait.includes('event.currentTarget')).toBe(false);
      }
    }
  });
});
