# TrustVault — Interview Learning Notes & Technical Defense Guide

**For the Candidate:** Use this guide to prepare for technical interviews and viva questions. Every explanation is written in clear, beginner-friendly language while upholding professional software engineering standards.

---

## 1. Architecture in Two Minutes

```
[Browser Client]
       │ (Same-Origin HTTPS Requests + HttpOnly Session Cookies)
       ▼
[Express 5 Server Tier]
   ├── Helmet (Security Headers & Content Security Policy)
   ├── CSRF Guard (sameOriginOnly rejects mismatched Origin on state-changing methods)
   ├── Rate Limiting (express-rate-limit on /api/auth/login: 10 attempts / 15 min)
   ├── Cookie Authentication Middleware (verifies JWT, auto-refreshes, loads role from DB)
   ├── Server-Side Authorization Engine (accessFor + getDocumentAccess)
   └── Append-Only Audit Service (writeAudit records attempt, success, and denied events)
       │                                                    │
       ▼                                                    ▼
[Supabase PostgreSQL Database]                      [Supabase Private Storage]
   ├── profiles (id, email, full_name, role)           └── trustvault-private bucket
   ├── documents (id, owner_id, title, storage_path)         ├── Uploads: file-type magic bytes check
   ├── document_permissions (can_read, can_edit)             └── Downloads: proxied with attachment,
   └── audit_events (reject_audit_mutation trigger)                          private/no-store, and nosniff
```

### The Request Flow:
1. **User Request:** The browser sends an HTTP request with the session cookie (`tv_access`).
2. **Authentication:** [`createAuthMiddleware`](src/middleware/auth.js) validates the Supabase Auth session. If expired, it automatically uses the refresh cookie (`tv_refresh`) to rotate the tokens. It then fetches the user's role from the PostgreSQL `profiles` table.
3. **Authorization Check:** For document endpoints, [`accessFor`](src/routes/documents.js) retrieves the document record and any active grants in `document_permissions`. [`getDocumentAccess`](src/security/access.js) computes permissions purely on the server:
   - Is user an **Administrator**? $\rightarrow$ Full access.
   - Is user the **Owner** (`document.owner_id === user.id`)? $\rightarrow$ Full access.
   - Does user have an explicit grant in `document_permissions`? $\rightarrow$ `can_edit` implies `can_read`.
   - None of the above? $\rightarrow$ Access denied (`403 Forbidden`).
4. **Audit Logging:** If access is denied, [`auditDenied`](src/services/audit.js) records the attempt. If granted, the mutation or download proceeds, and an audit record is written.
5. **Private Storage Retrieval:** Document downloads stream bytes through Express from the private Supabase Storage bucket. The client is never given a direct public URL to the file.

---

## 2. Core Concepts & Interview Q&A

### Q1: What is the difference between Authentication and Authorization?
* **Authentication (Who are you?):** Verifies the identity of the user. In TrustVault, this is handled via Supabase Auth email and password sign-in.
* **Authorization (What are you allowed to do?):** Determines whether the authenticated user has permission to perform a specific action on a specific resource. In TrustVault, this is evaluated per-document on the backend for every request.

### Q2: Why is a UI-only permission check dangerous?
* **Answer:** *"Hiding an 'Edit' or 'Delete' button in HTML/CSS only provides a clean user experience; it does not protect the resource. Any user can open browser developer tools, use Postman, or write a Python script to send HTTP requests directly to `/api/documents/:id`. Security boundaries must always be enforced on the server."*

### Q3: What is IDOR (Insecure Direct Object Reference) and how does TrustVault prevent it?
* **Answer:** *"IDOR occurs when an application exposes a direct reference to an internal object (like a database ID in the URL) without validating whether the user is authorized to access it. If user B changes the URL from `/api/documents/id-A` to access user A's file and the server returns it, that is an IDOR vulnerability.*
* *TrustVault prevents IDOR by never assuming that possessing an ID implies ownership. For every request, [`accessFor`](src/routes/documents.js) fetches the document and active grants from the database and checks if the requester is the owner, an administrator, or has an active grant. If not, the server immediately returns `403 Forbidden` and logs a security denial."*

### Q4: What happens if an attacker probes guessed document IDs that are not UUIDs?
* **Answer:** *"In PostgreSQL, our document and audit ID columns are typed as `UUID`. If an attacker probes with random strings like `admin_doc` or `secret123`, Postgres would normally throw error `22P02: invalid input syntax for type uuid`, resulting in an unhandled 500 server crash. Furthermore, inserting that invalid string into the audit log would crash the audit query.*
* *We implemented strict UUID validation using [`isValidUuid`](src/services/audit.js). If an input is not a valid UUID format, [`fetchDocument`](src/routes/documents.js) immediately returns `null` (yielding a clean `404 Not Found`). In [`writeAudit`](src/services/audit.js), non-UUID probes store `document_id: null` and preserve the attacker's probed string inside the JSON `details.attempted_document_id` field so the attempt is recorded in the audit trail without crashing the database."*

### Q5: Why do edit grants imply read access?
* **Answer:** *"A user cannot meaningfully edit a document without being able to view what they are editing. In [`getDocumentAccess`](src/security/access.js), `can_edit === true` automatically grants `can_read: true`. However, permission management (granting/revoking access to others) and document deletion remain strictly reserved for the document owner and administrators."*

### Q6: How does immediate permission revocation work?
* **Answer:** *"Many systems generate pre-signed storage URLs with expiration times (e.g., 15 minutes) or cache permissions in memory. In those systems, if an owner revokes access, the revoked user can still download the file until the cache or signed URL expires.*
* *TrustVault avoids this entirely by never issuing pre-signed storage URLs to browsers and never caching authorization decisions. Every download must pass through `/api/documents/:id/download`. The server queries `document_permissions` from the database in real time. The moment an owner deletes a grant, the very next download attempt fails with `403 Forbidden`."*

### Q7: How is the audit trail protected against tampering?
* **Answer:** *"Our audit trail implements defense-in-depth:*
* *1. **Application tier:** Express exposes zero endpoints to edit or delete audit records.*
* *2. **Database tier:** In [`001_schema.sql`](database/001_schema.sql), we created a PostgreSQL trigger `audit_events_no_update` executing [`reject_audit_mutation()`](database/001_schema.sql) before any `UPDATE` or `DELETE` on `audit_events`. Any mutation raises an exception.*
* *3. **Row-level security:** RLS is enabled on `audit_events` with no client policies.*
* *We describe this as tamper-resistant against application users, rather than absolutely immutable, because a database superuser with direct SQL console access could alter schema objects."*

### Q8: What real AI mistakes were discovered during development, and how did you fix them?
* **Answer:** *"We caught and fixed three genuine defects introduced during scaffolding:*
* *1. **PostgreSQL UUID Type Crashes:** Guessed document IDs that were not UUIDs crashed the database with 22P02 type errors. We fixed this by adding regex UUID validation and sanitizing audit inserts.*
* *2. **Storage File Deletion on Partial Mutation Failure:** In `PATCH /api/documents/:id`, the catch block deleted the replacement file even if the database had already committed it. We added a `dbUpdated` flag so committed files are never wiped.*
* *3. **Asynchronous DOM Event State Loss:** In `public/app.js`, calling `event.currentTarget.reset()` after `await api('/api/documents', ...)` crashed with `'Cannot read properties of null (reading reset)'` because modern browsers clear `event.currentTarget` after an asynchronous tick. This caused the UI to show an error even though the server upload had succeeded. We fixed this by capturing `formElement = event.currentTarget` synchronously before the `await` and separating API calls from UI cleanup."*

---

## 3. What Is Verified vs What Remains

* **Empirically Verified (26/26 Automated Tests Passing):**
  * IDOR prevention across all CRUD and download routes.
  * Guessed document IDs and malformed UUID safety.
  * Direct API requests bypassing UI restrictions.
  * Immediate permission revocation lifecycle.
  * Magic byte MIME validation rejecting spoofed files.
  * Role-based access control and administrator audit viewing.
  * Asynchronous event target DOM safety.
* **Verified in Live Supabase:**
  * Administrator, owner, and viewer profiles active in database.
  * Real document uploads stored in private `trustvault-private` bucket.
  * Real audit logs recording attempt, success, and admin view events.
* **Remaining Deployment Dependencies:**
  * Render production deployment with HTTPS and production cookie flags (`secure: true`).
  * Rate-limiting proxy trust (`app.set('trust proxy', 1)`) in live multi-IP environment.
