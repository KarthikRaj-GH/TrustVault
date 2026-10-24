# AI-Assisted Development Log — TrustVault

This file documents the development history of the TrustVault project for the Snovasys Fresher Hiring Challenge. Each dated entry captures the actual prompt/request, AI output, specific defects or limitations identified, corrective changes made, empirical test verification, and commit links.

---

## 2026-10-24 — Entry 1: Initial AI-Assisted TrustVault Scaffold

### Prompt / Request
ChatGPT was asked to assist in scaffolding the initial structure for the TrustVault hiring challenge, focusing on per-document access control, Supabase authentication, and an audit trail, while maintaining full developer accountability.

### AI Output
Generated an initial project structure containing an Express backend, Supabase client initialization, central access-decision helper (`getDocumentAccess`), PostgreSQL schema draft (`001_schema.sql`), basic single-page frontend (`public/`), threat register draft (`THREATS.md`), and unit tests for access decisions (`tests/access.test.js`).

### What Was Wrong or Needed Verification
1. The scaffold was completely untested against real HTTP routes; zero route-level or integration tests existed.
2. `supertest` was listed in `devDependencies` in `package.json` but completely unused.
3. Storage bucket privacy, cookie configurations, and error paths had not been validated against real or simulated network environments.
4. The database migration and immutability triggers had not been applied or tested.

### What I Changed and Why
Retained the scaffold as a baseline and transitioned the project to Antigravity for comprehensive code review, defensive security hardening, and test-driven verification.

### Verification
Ran initial test suite:
```text
npm test
✓ tests/access.test.js (9 tests passed)
```
Only 9 standalone unit tests ran; no HTTP endpoints were verified.

### Evidence
- Test output: 9 passed (unit only).
- Commit: Baseline scaffold established before repository initialization.

### My Explanation
"AI is valuable for generating architectural boilerplate, but generated code must never be trusted blindly. The initial scaffold lacked route-level verification and real-world failure handling, requiring rigorous inspection and empirical testing before it could be considered secure."

---

## 2026-10-24 — Entry 2: Security Hardening, UUID Input Sanitization, and Route Testing

### Prompt / Request
Antigravity was asked to inspect all codebase files, check toolchain versions, install dependencies, audit the implementation status of all 10 required capabilities, fix genuine security defects in reviewable stages, and add automated route tests for unauthorized document access, guessed document IDs, direct API bypasses, and immediate permission revocation.

### AI Output
Antigravity audited the entire codebase and uncovered four critical defects:
1. **PostgreSQL UUID Type-Cast 500 Crash:** In PostgreSQL, `documents.id` and `audit_events.document_id` are typed as `UUID`. Querying arbitrary non-UUID strings (`admin_doc`, `123`, `../../etc`) caused PostgreSQL error `22P02: invalid input syntax for type uuid`, crashing Express into an unhandled 500 response.
2. **Audit Logging Failure on Malformed Probes:** When `auditDenied` attempted to log a non-UUID probe, `writeAudit` tried to insert the invalid string into `audit_events.document_id`, causing the audit insert to crash and preventing security probes from being recorded.
3. **Dangling Storage File on `PATCH` Partial Failure:** In `PATCH /api/documents/:id`, the `catch` block unconditionally removed the new storage file. If the database update had already succeeded but a subsequent audit write failed, deleting the storage file left the database pointing to a non-existent file, corrupting the document.
4. **Missing Audit on Viewer Upload Denial:** `POST /api/documents` rejected viewers with 403 but forgot to call `auditDenied(admin, req, 'document_upload')`.

### What Was Wrong or Needed Verification
Route-level authorization, anti-IDOR protections, and immediate permission revocation existed only in theory. There was no automated proof that revoking a grant immediately stops access on the very next HTTP request.

### What I Changed and Why
1. Added strict `isValidUuid` validation in `src/services/audit.js` and `src/routes/documents.js`. Non-UUID queries return a clean `404 Not Found` without hitting Postgres.
2. Sanitized audit logging: if an attempted document ID is not a UUID, `document_id` is set to `null` and the raw probed string is safely stored in `details.attempted_document_id`.
3. Guarded `PATCH /api/documents/:id` with a `dbUpdated` flag so committed storage files are preserved if a later step fails.
4. Added `auditDenied` call on viewer upload denial.
5. Normalized `req.user` in `src/middleware/auth.js` to provide both `full_name` and `fullName` to fix session restore state.
6. Created `tests/mockSupabase.js` (in-memory Supabase mock) and `tests/routes.test.js` with 15 integration tests covering IDOR, direct API calls, guessed IDs, and revocation.

### Verification
Command executed: `npm test` (`vitest run`).
```text
✓ tests/access.test.js (10 tests) 7ms
✓ tests/routes.test.js (15 tests) 173ms
Test Files: 2 passed (2)
Tests: 25 passed (25)
Duration: 983ms
```

### Evidence
- Test output: 25 tests passed across unit and route suites.
- Commit: `b74b8b2ca76c9ec194a867d61001d5d13250d71d` ([Commit Link](https://github.com/KarthikRaj-GH/TrustVault/commit/b74b8b2ca76c9ec194a867d61001d5d13250d71d))

### My Explanation
"Real-world security requires defensive programming at system boundaries. Validating UUID syntax prevents database type crashes, and sanitizing the audit logger ensures that attacker probing attempts are captured in the security audit trail rather than failing the logging query. Furthermore, our automated route tests prove that immediate revocation works—the moment an owner revokes access, the next download attempt is blocked with 403 Forbidden."

---

## 2026-10-24 — Entry 3: Version Control Establishment and .gitignore Hardening

### Prompt / Request
Candidate approved initializing Git inside the `trustvault` folder, inspecting staged files, verifying that secrets and `node_modules` were excluded, running `git diff --cached --check`, and creating the initial baseline commit.

### AI Output
Antigravity identified `trustvault` as the single proper repository root (to ensure `package.json` and `README.md` reside at the top level for Render deployment and GitHub rendering). It hardened `.gitignore` to explicitly exclude `.env`, `.env.*`, `node_modules/`, debug logs, and OS/IDE clutter while retaining `package-lock.json` and `.env.example`.

### What Was Wrong or Needed Verification
Running `git diff --cached --check` detected trailing blank lines at the end of `.gitignore` and `PROMPTS.md` (exit code 1). Staged diff needed to be scanned to guarantee zero secret keys were included.

### What I Changed and Why
1. Cleaned trailing blank lines in `.gitignore` and `PROMPTS.md`; re-ran `git diff --cached --check` which passed with exit code 0.
2. Verified all 28 staged files using `git ls-files` and checked for private key patterns (`eyJ...`, `sbp_...`).
3. Created the baseline local commit with message: `chore: establish TrustVault baseline after local tests`.

### Verification
Commands executed:
```powershell
git -C ./trustvault diff --cached --check   # Returned 0
git -C ./trustvault commit -m "chore: establish TrustVault baseline after local tests"
git -C ./trustvault rev-parse HEAD         # b74b8b2ca76c9ec194a867d61001d5d13250d71d
```

### Evidence
- Staged file summary: 28 files, 5,142 insertions.
- Commit hash: `b74b8b2ca76c9ec194a867d61001d5d13250d71d`.

### My Explanation
"Establishing a clean version control baseline with verified `.gitignore` rules ensures that private credentials and temporary build artifacts can never leak into public repositories. Whitespace checks enforce code formatting hygiene from the very first commit."

---

## 2026-10-24 — Entry 4: GitHub Remote Setup, Master Branch Push, and Daemon Startup

### Prompt / Request
Candidate provided public GitHub repository URL (`https://github.com/KarthikRaj-GH/TrustVault.git`), saved `.env` locally, and requested adding remote `origin`, pushing the existing `master` branch with upstream tracking, inspecting `.env` safely without printing secret values, and starting the development server.

### AI Output
Antigravity inspected the working directory, confirmed `origin` remote, performed a pre-push `ls-remote` confirming the remote repository was empty, and pushed `master` to GitHub. It inspected `.env` using a PowerShell script that verified all 8 variables were defined without echoing values. It started `npm run dev` (`node --watch src/server.js`) in daemon mode.

### What Was Wrong or Needed Verification
Need to confirm that the server started successfully, bound to port 3000, and served valid responses without exposing any sensitive configuration in stdout.

### What I Changed and Why
1. Configured remote `origin` to `https://github.com/KarthikRaj-GH/TrustVault.git`.
2. Pushed `master` branch to GitHub without force-pushing.
3. Started server daemon on port 3000.
4. Probed `/api/health` via `curl` to verify HTTP 200 and response headers.

### Verification
Command executed:
```powershell
git -C ./trustvault push -u origin master
# branch 'master' set up to track 'origin/master'.
curl.exe -s -i http://localhost:3000/api/health
# HTTP/1.1 200 OK
# Content-Type: application/json; charset=utf-8
# {"status":"ok","service":"trustvault"}
```

### Evidence
- GitHub repository URL: [https://github.com/KarthikRaj-GH/TrustVault](https://github.com/KarthikRaj-GH/TrustVault)
- Commit URL: [https://github.com/KarthikRaj-GH/TrustVault/commit/b74b8b2ca76c9ec194a867d61001d5d13250d71d](https://github.com/KarthikRaj-GH/TrustVault/commit/b74b8b2ca76c9ec194a867d61001d5d13250d71d)
- Health check: 200 OK.

### My Explanation
"Separating secret management from code deployment is fundamental. By keeping `.env` strictly local and validating configuration existence without outputting values, we protect privileged database keys while verifying operational readiness."

---

## 2026-10-24 — Entry 5: Diagnosis and Fix of the Upload Event Handler Bug and Duplicate Record Analysis

### Prompt / Request
The candidate reported a real UI error during document upload: `"Cannot read properties of null (reading 'reset')"`. After page refresh, three identical-looking document entries titled `"TrustVault Demo Document"` and multiple audit events appeared. The candidate asked Antigravity to investigate using read-only checks without deleting data or assuming upload success, fix the root cause, inspect related handlers, and add regression tests.

### AI Output
Antigravity investigated `public/app.js` and discovered a classic asynchronous DOM event defect:
In modern browsers, `event.currentTarget` points to the form element only during the synchronous event dispatch phase. Once execution yields across an `await` tick (`await api('/api/documents', ...)`), the browser resets `event.currentTarget` to `null`.
In `#uploadForm`:
```javascript
const result = await api('/api/documents', { method: 'POST', body: form });
event.currentTarget.reset(); // Threw TypeError: Cannot read properties of null (reading 'reset')
```
Because `event.currentTarget.reset()` threw an error, execution jumped to the `catch` block which displayed the error in red. The server upload had **already succeeded** (HTTP 201), but the user believed it failed and clicked Upload two more times. Upon page refresh, all 3 successfully created documents were displayed.

### What Was Wrong or Needed Verification
1. `event.currentTarget` was accessed after `await` in `#uploadForm`, `#loginForm`, and `#shareForm`.
2. Post-action UI errors obscured successful server operations, creating user confusion.
3. The 3 existing document records and audit logs needed read-only verification to prove they were genuine server creations rather than database corruption.

### What I Changed and Why
1. In `public/app.js`, captured `const formElement = event.currentTarget;` synchronously at the top of `#uploadForm`, `#loginForm`, and `#shareForm` submit handlers before any `await`.
2. Separated the API network request from post-action UI updates with dedicated try/catch blocks so client DOM errors never misreport a successful server upload as an error.
3. Executed a read-only script querying Supabase PostgreSQL and Storage:
   - Proved that all 3 documents (`ee84827e...`, `b04bae06...`, `25427dc1...`) had unique UUIDs, valid storage paths, and paired `attempt` and `success` audit events.
   - Confirmed files exist in private storage bucket `trustvault-private`.
4. Added a client safety regression test in `tests/access.test.js` verifying that `public/app.js` contains no references to `event.currentTarget` after `await`.

### Verification
Command executed: `npm test` (`vitest run`).
```text
✓ tests/access.test.js (11 tests) 9ms
✓ tests/routes.test.js (15 tests) 181ms
Test Files: 2 passed (2)
Tests: 26 passed (26)
Duration: 998ms
```
Read-only Supabase query output confirmed 3 valid documents and 7 audit events in PostgreSQL.

### Evidence
- Test output: 26 tests passed.
- Supabase read-only query output: 3 documents in `documents` table, 3 storage objects in `trustvault-private`, 7 audit events in `audit_events`.

### My Explanation
"DOM events have a synchronous lifecycle. When handling asynchronous form submissions, references to `event.currentTarget` must be captured synchronously into local constants before the first `await`. Furthermore, user feedback must decouple network status from UI cleanup: if an API call succeeds, the application should never report failure just because a subsequent DOM cleanup step failed."
