# TrustVault Threat Register & Security Verification Matrix

**Hiring Challenge Project — Snovasys Fresher Challenge**
**Repository:** [https://github.com/KarthikRaj-GH/TrustVault](https://github.com/KarthikRaj-GH/TrustVault)

> [!IMPORTANT]
> This document distinguishes verified empirical evidence (local automated unit tests, mock integration tests, and live Supabase queries) from unverified assumptions and deployment dependencies. Do not describe this service as having passed an external penetration test.

---

## 1. Status Definitions

* **Unit Verified:** Code logic verified by automated Vitest unit tests without network.
* **Mock Integration Verified:** End-to-end Express route and middleware execution verified using Supertest against stateful in-memory Supabase mocks (`tests/routes.test.js`).
* **Live Supabase Verified:** Tested directly against the real Supabase PostgreSQL database and Storage bucket (`trustvault-private`).
* **Deployment Dependency:** Dependent on production environment configuration (HTTPS, Render proxy trust, origin headers).

---

## 2. Threat & Control Matrix

### Threat 1: Unauthorized Document Access & Insecure Direct Object References (IDOR)
* **Attack Scenario:** An authenticated viewer alters the document UUID parameter in `/api/documents/:id` or `/api/documents/:id/download` to access another user's private document.
* **Affected Component:** `src/routes/documents.js`, `src/security/access.js`
* **Mitigation in Code:** [`accessFor`](src/routes/documents.js) retrieves the document from the database and passes user, document, and active grants to [`getDocumentAccess`](src/security/access.js). It computes permissions on the server for every single request. If `access.canRead` is false, it immediately records an audit denial and halts with `403 Forbidden`.
* **Tests & Verification:**
  * Unit: `tests/access.test.js` (`denies a viewer with no grant`)
  * Mock Integration: `tests/routes.test.js` (`denies a viewer trying to read another user document with 403`)
* **Observed Result:** Direct GET request for ungranted document returned `HTTP 403` with payload `{"error":"You do not have access to this document."}` and an `outcome: 'denied'` audit event was recorded.
* **Remaining Limitations:** Live multi-user concurrency testing under heavy load remains to be benchmarked.

---

### Threat 2: Guessed Document IDs & Malformed UUID Crashes (Input Validation)
* **Attack Scenario:** An attacker fuzzes document endpoints with arbitrary strings (`admin_secret`, `123`, `../../etc`) to trigger unhandled exceptions, database error disclosure, or denial of service.
* **Affected Component:** `src/routes/documents.js`, `src/services/audit.js`, PostgreSQL schema (`001_schema.sql`)
* **Mitigation in Code:** In PostgreSQL, `documents.id` and `audit_events.document_id` are typed as `UUID`. Querying invalid UUIDs causes PostgreSQL error `22P02`. We implemented [`isValidUuid`](src/services/audit.js): [`fetchDocument`](src/routes/documents.js) immediately returns `null` for non-UUID strings without querying Postgres, returning `404 Not Found`. In [`writeAudit`](src/services/audit.js), non-UUID probes leave `document_id: null` while safely recording the probed input in `details.attempted_document_id`.
* **Tests & Verification:**
  * Unit: `tests/access.test.js` (`validates UUID format strictly`)
  * Mock Integration: `tests/routes.test.js` (`safely handles malformed non-UUID guessed document IDs with 404 and logs the probe`, `returns 404 for non-existent valid UUID and captures denial`)
* **Observed Result:** `GET /api/documents/guessed_admin_secret_doc` returned clean `404 Not Found` without 500 error; audit event recorded `document_id: null` and `attempted_document_id: 'guessed_admin_secret_doc'`.
* **Remaining Limitations:** None in application routing; input length is also bounded.

---

### Threat 3: Direct API Requests Bypassing Frontend Controls
* **Attack Scenario:** An attacker sends raw `POST`, `PATCH`, or `DELETE` requests directly using tools like `curl` or Postman to manipulate documents or permissions where UI buttons are hidden.
* **Affected Component:** `src/routes/documents.js`
* **Mitigation in Code:** All route handlers independently check permissions via `accessFor`. Viewers are blocked from `POST /api/documents` (upload), `PATCH /api/documents/:id` (edit), `DELETE /api/documents/:id` (delete), and `/api/documents/:id/permissions` (grant/revoke).
* **Tests & Verification:**
  * Mock Integration: `tests/routes.test.js` (`denies viewer direct API request to edit an unshared document`, `denies viewer direct API request to delete an unshared document`, `denies viewer direct API request to view or grant permissions`, `denies viewer from uploading documents and audits the denial`)
* **Observed Result:** Every unauthorized direct mutation returns `HTTP 403 Forbidden` with an audit denial event.
* **Remaining Limitations:** None; frontend is treated strictly as an untrusted interface.

---

### Threat 4: Stale Authorization After Permission Revocation (Lack of Immediate Revocation)
* **Attack Scenario:** A document owner revokes a user's access, but the user continues to download or view the document using cached permissions, uninvalidated sessions, or pre-signed URLs.
* **Affected Component:** `src/routes/documents.js`, `src/services/audit.js`
* **Mitigation in Code:** Document downloads are proxied through `/api/documents/:id/download`. The server reloads `document_permissions` from PostgreSQL on every request. Pre-signed URLs are not issued to clients. When `DELETE /api/documents/:id/permissions/:userId` deletes the grant, subsequent requests cannot find the grant and fail immediately.
* **Tests & Verification:**
  * Mock Integration: `tests/routes.test.js` (`verifies the full lifecycle: unauthorized -> granted read -> download -> revoked -> immediate denial`)
* **Observed Result:** User could download file immediately after grant (`200 OK`); immediately following revocation, the very next download request returned `403 Forbidden`.
* **Remaining Limitations:** Already downloaded copies on a user's client machine cannot be remotely deleted.

---

### Threat 5: Role Privilege Escalation via Client Modification
* **Attack Scenario:** A user edits local browser storage, DOM, or cookies to change their role from `viewer` to `document_owner` or `administrator`.
* **Affected Component:** `src/middleware/auth.js`, Supabase `profiles` table
* **Mitigation in Code:** User roles are never accepted from client requests or JWT metadata. Upon validating the session token, [`authenticate`](src/middleware/auth.js) queries `profiles.role` directly from PostgreSQL using the server-side service role key. There is no self-registration or role update endpoint.
* **Tests & Verification:**
  * Live Supabase Verified: Read-only check verified `profiles` table contains provisioned roles (`administrator`, `document_owner`, `viewer`).
  * Mock Integration: `tests/routes.test.js` (`returns provisioned user profile on valid session`)
* **Observed Result:** Role loaded from database profile row; client tampering with local state cannot affect server decision.
* **Remaining Limitations:** Initial user provisioning requires administrative access in Supabase.

---

### Threat 6: Private Document Exposure via Public Storage URLs
* **Attack Scenario:** An attacker guesses a storage object path or tries to access files directly from the Supabase Storage CDN endpoint without authentication.
* **Affected Component:** Supabase Storage configuration, `src/routes/documents.js`
* **Mitigation in Code:** The bucket `trustvault-private` is configured as **private** (public access disabled). Files are addressed with randomized UUID paths (`owner_id/UUID.ext`). Direct unauthenticated GET requests to the Supabase Storage CDN are rejected. All legitimate downloads must pass through Express `/api/documents/:id/download`, which enforces authorization, writes an audit record, and adds security headers (`Content-Disposition: attachment; filename=...`, `Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff`).
* **Tests & Verification:**
  * Live Supabase Verified: Confirmed private bucket configuration and server-brokered storage downloads.
  * Mock Integration: `tests/routes.test.js` (`verifies private storage headers and download payload`)
* **Observed Result:** Storage files are only accessible via authenticated Express routes with verified ACLs.
* **Remaining Limitations:** Dependent on administrator keeping bucket privacy enabled in Supabase dashboard.

---

### Threat 7: Malicious File Upload (Spoofed MIME Types & Oversized Files)
* **Attack Scenario:** An attacker uploads an executable, script, or HTML file disguised as a PDF or image, or sends an oversized file to exhaust server resources.
* **Affected Component:** `src/routes/documents.js` ([`validateUpload`](src/routes/documents.js))
* **Mitigation in Code:** Multer parses file streams into memory up to a hard cap. [`validateUpload`](src/routes/documents.js) inspects file header magic bytes using `file-type` (`fileTypeFromBuffer`). Only `application/pdf`, `image/png`, and `image/jpeg` magic numbers are accepted. MIME headers declared by the browser are ignored. Upload size is enforced against `MAX_UPLOAD_MB`.
* **Tests & Verification:**
  * Mock Integration: `tests/routes.test.js` (`rejects unsupported file MIME type with 415`, `accepts valid PNG image upload by document owner`)
  * Live Supabase Verified: A real upload succeeded after the form-reset fix and appeared in the app document list. PNG acceptance and spoofed-MIME rejection remain unverified.
* **Observed Result:** Text file renamed to `.pdf` rejected with `HTTP 415 Unsupported Media Type`. Valid image accepted with `HTTP 201 Created`.
* **Remaining Limitations:** Deep file inspection (e.g. antivirus/malware scanning or PDF embedded script parsing) is not included; file is served with `attachment` and `nosniff` headers to prevent browser execution.

---

### Threat 8: Tampering with Audit Trail Records
* **Attack Scenario:** A compromised account attempts to modify (`UPDATE`) or erase (`DELETE`) log rows in `audit_events` to cover unauthorized access.
* **Affected Component:** `database/001_schema.sql`, `src/services/audit.js`
* **Mitigation in Code:** No audit modification or deletion endpoints exist in Express. In PostgreSQL, trigger `audit_events_no_update` executes [`reject_audit_mutation()`](database/001_schema.sql), raising an exception on any row `UPDATE` or `DELETE`. Row Level Security (RLS) is enabled with no client policies.
* **Tests & Verification:**
  * Schema & Trigger Inspection: Verified `reject_audit_mutation` trigger definition in `001_schema.sql`.
  * Live Supabase Verified: Audit events were inspected via a read-only query. The schema includes a trigger intended to reject audit-row UPDATE/DELETE, but a live attempt to mutate an audit record was not demonstrated; database-level append-only enforcement remains unverified.
* **Observed Result:** Audit records are immutable through standard application connections.
* **Remaining Limitations:** A database superuser or project owner possessing direct SQL access can drop triggers or alter tables. Immutability is tamper-resistant at the application tier, not cryptographic proof.

---

### Threat 9: Unauthorized Inspection of Audit Logs
* **Attack Scenario:** A document owner or viewer attempts to view organizational audit records via `/api/admin/audit`.
* **Affected Component:** `src/routes/admin.js`
* **Mitigation in Code:** `/api/admin/audit` checks `req.user.role === 'administrator'`. If non-admin, it immediately logs `admin_audit_view` with `outcome: 'denied'` and returns `HTTP 403 Forbidden`.
* **Tests & Verification:**
  * Mock Integration: `tests/routes.test.js` (`denies non-admin accounts from viewing admin audit logs`, `allows administrator to view recent audit events`)
  * Live Supabase Verified: Inspected audit event ID 7 (`admin_audit_view`, `outcome: 'success'`, `row_count: 6`) after admin accessed the view.
* **Observed Result:** Non-admins receive `HTTP 403`; admins receive `HTTP 200` with the log array.
* **Remaining Limitations:** None.

---

### Threat 10: Partial Mutation Failure & Storage-Database Inconsistency
* **Attack Scenario:** A document edit replaces a storage file, updates the database, but a subsequent audit write or network step fails.
* **Affected Component:** `src/routes/documents.js` (`PATCH /api/documents/:id`)
* **Mitigation in Code:** Previously, the `catch` block unconditionally removed `newStoragePath` on any failure. If the database update had already succeeded, deleting `newStoragePath` created a dangling database reference. Fixed by tracking `dbUpdated`: `newStoragePath` is only removed if the database update has NOT yet occurred.
* **Tests & Verification:**
  * Code Inspection: Verified `dbUpdated` logic in `src/routes/documents.js`.
* **Observed Result:** Committed storage files are preserved, preventing file corruption.
* **Remaining Limitations:** PostgreSQL and Supabase Storage do not share a two-phase commit (2PC) transaction. A network disconnection between database update and storage cleanup of the old file can leave an orphaned file in storage.

---

### Threat 11: Asynchronous Client-Side DOM State Loss (The Upload UI Error)
* **Attack Scenario:** A form submission handler accesses `event.currentTarget` after an asynchronous `await api(...)` call. Because the browser sets `event.currentTarget` to `null` once the synchronous event phase ends, calling `.reset()` throws `Cannot read properties of null`, making a successful server upload appear as a client error.
* **Affected Component:** `public/app.js` (`#uploadForm`, `#loginForm`, `#shareForm`)
* **Mitigation in Code:** Captured `const formElement = event.currentTarget;` synchronously at handler entry. Separated API network call from post-action UI updates with dedicated try/catch blocks so UI errors do not misreport successful server operations.
* **Tests & Verification:**
  * Unit: `tests/access.test.js` (`does not reference event.currentTarget after an await in public/app.js`)
  * Live Supabase Verified: Discovered 3 successful uploads from earlier attempts that failed on client `.reset()`.
* **Observed Result:** Handlers safely access the captured form element; `26/26` automated tests pass.
* **Remaining Limitations:** Client-side JavaScript execution depends on modern browser standards compliance.

---

## 3. Verification Summary Table

| Category | Control | Verification Level | Test Evidence |
|---|---|---|---|
| Authorization | IDOR Prevention | Mock Integration | `tests/routes.test.js` |
| Authorization | Guessed ID Safety | Unit + Mock Integration | `tests/access.test.js`, `tests/routes.test.js` |
| Authorization | Immediate Revocation | Mock Integration | `tests/routes.test.js` |
| Authorization | Non-Admin Audit Block | Mock Integration | `tests/routes.test.js` |
| Authentication | Session Cookies & Role | Unit + Live Supabase | `tests/access.test.js`, Supabase DB |
| Storage | Magic Byte MIME Check | Mock Integration | `tests/routes.test.js` |
| Storage | Private Bucket Proxy | Mock Integration + Live | `tests/routes.test.js`, Supabase Storage |
| Audit Trail | Immutability Trigger | Schema Inspection | `database/001_schema.sql` |
| Audit Trail | Denied Action Logging | Mock Integration + Live | `tests/routes.test.js`, Supabase DB |
| Frontend | Event Target Safety | Unit Test | `tests/access.test.js` |
| Production | HTTPS & CSRF Origin | Code Inspection | `src/middleware/csrf.js` (Pending Render deploy) |
