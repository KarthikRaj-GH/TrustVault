# AI-assisted development log

This file must be updated throughout development. The hiring challenge asks for at least five dated entries and at least two entries about authorization, access control, or the audit trail. Each entry should accurately capture the real request, output, defect or limitation discovered, correction, verification and actual commit link. Do not invent mistakes, test results, or commit URLs.

## Entry template (copy once per real work session)

```markdown
## YYYY-MM-DD — Short task title

### Prompt / request
[Paste the actual prompt or give a fair summary of it. Name the tool used.]

### AI output
[Describe the actual generated code, recommendation, or files.]

### What was wrong or needed verification
[State the specific defect/limitation found, or what was inspected when no defect was found.]

### Verification
[Actual command/request and actual observed result. Include failures; do not claim a test ran if it did not.]

### What I changed and why
[Describe the real correction or explain why the inspected implementation was retained.]

### Evidence
- Test output: [actual result]
- Commit: [actual GitHub commit URL, added after the commit exists]

### My explanation
[What I learned and how I would explain the decision in an interview.]
```

## 2026-10-24 — Initial AI-assisted TrustVault scaffold

### Tool and request
ChatGPT was asked to help start the TrustVault hiring-challenge project and address the concern that using Antigravity might make judges think no work was done by the candidate.

### Output created
This initial scaffold contains an Express application structure, a Supabase integration, a central per-document access-decision function, a SQL schema draft, a basic frontend, an initial threat register, and local unit tests. It is a starter implementation, not a completed or security-audited system.

### What needs checking
The scaffold has not yet been connected to a real Supabase project or deployed. The unit tests cover the standalone access-decision helper and filename/search helpers; they do not prove that every live HTTP route, Storage policy, cookie setting, or database operation is secure. Integration tests and partial-failure testing remain outstanding.

### Verification
To be completed truthfully after running `npm install` and `npm test` in this project, then after configuring and testing Supabase. Do not mark deployment or integration checks as passed until they have actually run.

### Correction / next action
Open the scaffold in Antigravity, inspect the files, run its tests, and review the access-control and failure paths before committing. Add a real commit URL only after a commit exists.

### Commit
Not yet created. Add the actual GitHub commit URL here after publishing the work.

### Interview explanation
I used AI to accelerate scaffolding, but the application must be validated through code review and actual security tests. The core rule is that the server checks the current user's permission for the specific document on each request; hiding a UI button is not authorization.

## 2026-10-24 — Security hardening, UUID input sanitization, and automated route testing in Antigravity

### Prompt / request
The candidate asked Antigravity to inspect the existing TrustVault files, check environment versions, install dependencies, run tests, identify the status of the ten required capabilities, fix genuine errors in small reviewable stages (prioritizing authorization, private storage, revocation, and audit trails), add automated security tests for unauthorized access and revocation, and document genuine findings.

### AI output
Antigravity inspected all source files, schemas, and configurations. It discovered several genuine security and operational issues:
1. When clients probed non-UUID document IDs, PostgreSQL threw error `22P02: invalid input syntax for type uuid`, resulting in an unhandled 500 error instead of a clean 404/400.
2. In `audit.js`, inserting a non-UUID probe into `audit_events.document_id` failed PostgreSQL's UUID column check, preventing security probe attempts from being recorded.
3. In `PATCH /api/documents/:id`, if database update succeeded but a subsequent audit write failed, the catch block deleted the new storage file, leaving the database pointing to a non-existent file (dangling storage reference).
4. In `POST /api/documents`, viewer upload denials were returned with 403 but lacked an `auditDenied` call, leaving a gap in the audit trail.
5. In `auth.js`, `req.user` only mapped `fullName` while the frontend expected `full_name`, breaking name display after session restoration.
6. Only 9 unit tests existed; zero route-level tests verified IDOR, direct API bypass, or immediate revocation.

### What was wrong or needed verification
1. The system needed defensive input validation to prevent SQL/PostgreSQL type-cast crashes on guessed IDs.
2. The audit trail needed to record non-UUID attack probes without crashing the database insert.
3. The partial-failure cleanup logic needed guarding so committed files are never deleted on audit failure.
4. The application needed automated proof that revoking a grant immediately stops access on the next request.

### Verification
Command executed: `npm test` (`vitest run`).
Observed result:
- `tests/access.test.js`: 10 passed (including new UUID validator unit test).
- `tests/routes.test.js`: 15 passed (testing unauthenticated access, IDOR defense, guessed IDs, direct API bypass, viewer upload denial, per-document ACLs, immediate revocation, spoofed MIME rejection, and admin audit viewing).
Total: 25 tests passed in 982ms.

### What I changed and why
1. Added strict UUID validation (`isValidUuid`) in `src/services/audit.js` and `src/routes/documents.js`. Non-UUID queries immediately return null/404, avoiding database type errors.
2. Sanitized audit logging: if an attempted document ID is not a UUID, `document_id` is set to null and the probed string is preserved in `details.attempted_document_id`.
3. Guarded `PATCH /api/documents/:id` with a `dbUpdated` flag so committed replacement files in storage are not wiped if a later audit step fails.
4. Added `auditDenied(admin, req, 'document_upload')` for viewer upload attempts.
5. Added `full_name` to `req.user` in `src/middleware/auth.js` for session restore consistency.
6. Created `tests/mockSupabase.js` and `tests/routes.test.js` providing 15 automated integration tests with `supertest`.

### Evidence
- Test output: 25 passed across 2 test files (duration: 982ms).
- Commit: Pending local git commit / GitHub remote push.

### My explanation
"Hiding a button in the frontend is not security. Our backend verifies authentication and evaluates authorization for every single HTTP request. We also hardened the service against real-world probing: non-UUID attacks no longer crash the database with type errors, and probes are safely recorded in the audit trail. Furthermore, our automated route tests prove that immediate revocation works—once an owner revokes access, the very next download request receives a 403 Forbidden."
