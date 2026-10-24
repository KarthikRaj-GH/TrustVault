# TrustVault

**Secure document sharing with per-document permissions, private storage, and an append-only audit trail.**

Built for the **Snovasys Fresher Hiring Challenge** (Deadline: October 25, 2026, 6:00 PM).
**Repository:** [https://github.com/KarthikRaj-GH/TrustVault](https://github.com/KarthikRaj-GH/TrustVault)

---

## 1. System Overview & Architecture

TrustVault is an enterprise-grade document sharing system where security boundaries are enforced exclusively on the server. The frontend user interface provides convenient controls, but every API route validates authentication, authorization, input syntax, and file integrity independently.

```
[Browser Client]
       │ (Same-Origin HTTPS Requests + HttpOnly Session Cookies)
       ▼
[Express 5 Server Tier]
   ├── Security Headers (Helmet CSP, X-Content-Type-Options: nosniff)
   ├── CSRF Guard (sameOriginOnly rejects mismatched Origin on state-changing methods)
   ├── Rate Limiting (express-rate-limit on /api/auth/login: 10 attempts / 15 min)
   ├── Session Authentication (verifies JWT, auto-refreshes, loads role from DB)
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

---

## 2. Core Security Capabilities

1. **Role-Based Access Control (RBAC):** Three distinct roles provisioned in PostgreSQL: `administrator`, `document_owner`, and `viewer`. Roles are loaded from the database profile, never trusted from client input.
2. **Per-Document Granular ACLs:** Explicit per-document permissions. Edit access implies read access. Only owners and administrators can manage permissions or delete documents.
3. **Insecure Direct Object Reference (IDOR) Defense:** Routes resolve document ownership and active grants on the server for every request. Possessing or guessing a document UUID grants no access.
4. **Input Syntax Validation:** UUID parameters are validated before hitting PostgreSQL. Malformed strings return clean `404 Not Found` without database cast errors (`22P02`), and probe attempts are safely recorded in audit logs.
5. **Immediate Permission Revocation:** The server checks active database grants on each request rather than caching decisions or issuing pre-signed URLs. Revocation takes effect on the very next request.
6. **Private File Storage & Content Validation:** Stored in a private Supabase Storage bucket (`trustvault-private`). Files are validated by inspecting binary magic numbers via `file-type` (`PDF`, `PNG`, `JPEG`); client-supplied MIME headers are ignored.
7. **Tamper-Resistant Audit Trail:** Application exposes no edit/delete endpoints for audit events. PostgreSQL trigger `audit_events_no_update` executes `reject_audit_mutation()` to raise an exception on any row `UPDATE` or `DELETE`.
8. **Administrative Oversight:** Dedicated `/api/admin/audit` endpoint restricted to administrators. Non-admin access attempts are blocked with `403` and logged.

---

## 3. Local Setup & Testing

### Prerequisites
* Node.js 20 or later
* npm
* A Supabase project with Authentication, PostgreSQL, and Storage enabled

### Setup Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/KarthikRaj-GH/TrustVault.git
   cd TrustVault
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the automated test suite:
   ```bash
   npm test
   ```
   *(All 26 automated unit and route integration tests run via Vitest).*
4. In your Supabase project SQL Editor, execute `database/001_schema.sql`.
5. Create a **private** bucket in Supabase Storage named `trustvault-private`.
6. Create provisioned test users in Supabase Auth and insert matching rows in `public.profiles` with roles `administrator`, `document_owner`, and `viewer`.
7. Copy `.env.example` to `.env` and fill in your Supabase credentials:
   ```env
   NODE_ENV=development
   PORT=3000
   APP_ORIGIN=http://localhost:3000
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_ANON_KEY=your-anon-key
   SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
   SUPABASE_BUCKET=trustvault-private
   MAX_UPLOAD_MB=10
   ```
8. Start the development server:
   ```bash
   npm run dev
   ```
9. Open `http://localhost:3000` in your browser. Verify the health check at `http://localhost:3000/api/health`.

---

## 4. Useful API Endpoints

| Method | Endpoint | Authorization Required | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | Public | Service health status |
| `POST` | `/api/auth/login` | Public (Rate-limited) | Sign in and set HttpOnly cookies |
| `POST` | `/api/auth/logout` | Authenticated | Clear session cookies |
| `GET` | `/api/auth/me` | Authenticated | Return current user profile & role |
| `GET` | `/api/documents` | Authenticated | List accessible documents for user |
| `POST` | `/api/documents` | Owner or Administrator | Upload validated file to private storage |
| `GET` | `/api/documents/:id` | Read Permission | Get document metadata |
| `GET` | `/api/documents/:id/download` | Read Permission | Stream file with attachment headers |
| `PATCH` | `/api/documents/:id` | Edit Permission | Update title, category, or file |
| `DELETE` | `/api/documents/:id` | Owner or Administrator | Delete file from storage and database |
| `GET` | `/api/documents/:id/permissions`| Owner or Administrator | List active permissions for document |
| `POST` | `/api/documents/:id/permissions`| Owner or Administrator | Grant read or edit permission |
| `DELETE` | `/api/documents/:id/permissions/:userId` | Owner or Administrator | Revoke user permission |
| `GET` | `/api/admin/audit` | Administrator | Query recent audit trail records |

---

## 5. Deployment on Render

1. Connect your public GitHub repository to a new **Render Web Service**.
2. **Build Command:** `npm install`
3. **Start Command:** `npm start`
4. Set environment variables in the Render dashboard:
   * `NODE_ENV=production`
   * `APP_ORIGIN=https://your-service-name.onrender.com`
   * `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_BUCKET`, `MAX_UPLOAD_MB`
5. Deploy and verify `/api/health`.

---

## 6. Verification & Test Evidence

* Automated Vitest Suite: **26 tests passing across 2 test files** (duration < 1.0s).
* Route Integration Suite (`tests/routes.test.js`): Covers unauthorized access, IDOR prevention, guessed document IDs, direct API bypasses, permission grants, and immediate revocation.
* Unit Test Suite (`tests/access.test.js`): Covers central access helper, role boundaries, input sanitization, UUID validation, and client-side DOM event safety.
* Threat Register: Full verification matrix available in [`THREATS.md`](THREATS.md).
* Development History: Dated session logs available in [`PROMPTS.md`](PROMPTS.md).
