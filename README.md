# TrustVault

**Secure document sharing with per-document permissions and an audit trail.** This is an AI-assisted hiring-challenge project. Its implementation and security claims must be verified against actual tests and the deployed environment before submission.

## Current implementation scope

The starter implementation includes:

- Three provisioned roles: `administrator`, `document_owner`, and `viewer`.
- Supabase Auth password sign-in with `HttpOnly`, `SameSite=Strict` cookies and refresh handling.
- Server-side checks for every document metadata, download, edit, delete, grant, and revoke route.
- Explicit per-document read/edit grants; edit grants imply read access.
- Private Supabase Storage uploads, using detected file signatures and a configurable size limit. Initial supported types are PDF, PNG, and JPEG.
- Audit records for document views/downloads, uploads, edits, deletion, permission changes, denials and administrator audit viewing.
- Application-level append-only audit writes and a database trigger rejecting audit-row updates/deletes.
- Search by title and category. Date query parameters are also supported by the API.
- Automated unit tests for access-decision logic and input-safety helpers.

**Do not describe this as fully security-audited.** The current tests are not a substitute for end-to-end tests against a configured Supabase project and the deployed service. Inspect `THREATS.md` for unverified areas. Before submission, add and run live integration tests for cross-user access, direct API requests, and revocation.

## Requirements

- Node.js 20 or later
- npm
- A Supabase project with Authentication, PostgreSQL, and Storage enabled
- Git (for version control)

## Local setup

1. Create a Supabase project.
2. In Supabase SQL Editor, run `database/001_schema.sql` on your new project.
3. In Authentication, create at least three test users (administrator, document owner, viewer). Use fake credentials and demo files only.
4. For each Auth user, add a matching `public.profiles` row using the exact Auth user UUID, email, full name and role. Never let a user assign their own role.
5. Create a **private** Storage bucket called `trustvault-private`. Set the file size limit to match the configured application limit.
6. Copy `.env.example` to `.env` and fill in your project's URL, publishable/anon key, and server-only service-role key. Do not commit `.env`.
7. Install dependencies and start the app:

   ```bash
   npm install
   npm test
   npm run dev
   ```

8. Open `http://localhost:3000`.

The health endpoint is `http://localhost:3000/api/health`.

## Environment variables

| Variable | Purpose |
|---|---|
| `NODE_ENV` | Use `production` in the deployed environment. |
| `PORT` | HTTP port; Render supplies its own `PORT`. |
| `APP_ORIGIN` | Exact site origin, such as `https://your-service.onrender.com`. Required in production. |
| `SUPABASE_URL` | Supabase project URL. |
| `SUPABASE_ANON_KEY` | Public/anon key used by the backend for password sign-in and refresh. |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-only privileged key. **Never put it in browser code or Git.** |
| `SUPABASE_BUCKET` | Private storage bucket name. Defaults to `trustvault-private`. |
| `MAX_UPLOAD_MB` | Maximum file size in MiB; 1–25. |

## Deployment on Render

1. Push the reviewed project to a public GitHub repository.
2. Create a Render Web Service connected to the repository.
3. Build command: `npm install`.
4. Start command: `npm start`.
5. Set `NODE_ENV=production`, `APP_ORIGIN` to the exact deployed HTTPS origin, and the Supabase environment variables in Render's environment settings.
6. Confirm the Supabase Storage bucket is private and that its name matches `SUPABASE_BUCKET`.
7. Deploy. Open `/api/health`, sign in using each demo role, and run the access-control checks before sharing the URL.

Do not store uploaded documents on Render's local filesystem. Do not use real confidential documents for the demo.

## Roles and access model

- **Administrator:** can read, edit, delete and manage documents; can view the administrative audit list. This is a deliberately privileged role and must be disclosed in the project explanation.
- **Document owner:** can read, edit, delete their own documents, and grant/revoke access to existing provisioned accounts.
- **Viewer:** has no document access by default; can read documents explicitly granted to them. A separate edit grant enables editing and implies read access.

The backend retrieves the authenticated identity and current role, loads the target document and its current grant, then makes an access decision for every request. The frontend only hides unavailable actions for usability; it is not the security boundary.

## Useful endpoints

| Method | Endpoint | Access |
|---|---|---|
| `GET` | `/api/health` | Public health check |
| `POST` | `/api/auth/login` | Public, rate-limited |
| `POST` | `/api/auth/logout` | Session cookie |
| `GET` | `/api/auth/me` | Authenticated |
| `GET` | `/api/documents` | Authenticated; only accessible documents are returned |
| `POST` | `/api/documents` | Document owner or administrator |
| `GET` | `/api/documents/:id` | Document read permission |
| `GET` | `/api/documents/:id/download` | Document read permission |
| `PATCH` | `/api/documents/:id` | Document edit permission |
| `DELETE` | `/api/documents/:id` | Owner or administrator |
| `GET` | `/api/documents/:id/permissions` | Owner or administrator |
| `POST` | `/api/documents/:id/permissions` | Owner or administrator |
| `DELETE` | `/api/documents/:id/permissions/:userId` | Owner or administrator |
| `GET` | `/api/admin/audit` | Administrator |

All state-changing requests are protected by a same-origin check. Browser session cookies are HttpOnly, so ordinary page JavaScript cannot read the token. Production must be served over HTTPS.

## Before calling the project ready

- Run `npm test` and preserve the actual output.
- Add end-to-end tests against a disposable Supabase project and the live deployment.
- Test guessed document IDs, direct API requests, denied downloads, access revocation, upload spoofing, and non-admin audit access.
- Review the actual behavior of audit write failures and file replacement/deletion failure paths.
- Confirm deployed seed users, role assignments and private Storage settings.
- Update `THREATS.md`, `PROMPTS.md` and this README to match verified behavior.
- Make meaningful Git commits as real changes are completed. Never invent commit history or test results.
