# TrustVault threat register

Status meanings:
- **Implemented, locally checked:** code exists and a local automated check supports the claim.
- **Needs integration verification:** the control exists in code but has not yet been tested against a configured deployment.
- **Known limitation:** do not represent this control as fully solved.

This file is a working threat register, not a claim that the application has passed a professional security audit.

| Threat | Mitigation in this codebase | Verification status | Remaining work |
|---|---|---|---|
| A signed-in user guesses another document UUID (IDOR) | The document routes load the target document and evaluate owner/admin/grant access on the server for every request. UUID syntax is validated to prevent PostgreSQL 22P02 type errors. | **Implemented, locally checked:** Automated route tests (`tests/routes.test.js`) verify that ungranted UUID access returns 403, non-existent UUIDs return 404, and malformed IDs return 404 without database crashes; denials and probes are recorded in audit logs. | Run two-account tests against live configured Supabase project and deployed Render service. |
| A user has no access grant | No grant means no read/edit/manage access; denied routes return 403 and record a denied audit record. | **Implemented, locally checked:** Automated route tests verify that GET, download, PATCH, DELETE and permission management routes return 403 for unauthorized users. | Test against live Supabase database. |
| An owner revokes an access grant | Revocation deletes the grant; the backend reloads the current grant on each later request rather than caching it. | **Implemented, locally checked:** Automated route tests verify full lifecycle: viewer downloads successfully -> owner revokes -> viewer's immediate next download attempt returns 403 Forbidden. | Verify with multiple concurrent requests in live deployment. |
| A user edits their role in the browser | Role is loaded from the server-managed `profiles` table after identity verification. There is no self-registration or role-edit endpoint. | Code inspection and route test checked (role in session loaded from profile data). | Verify live Supabase RLS policies and admin provisioning. |
| Privileged database key leaks into client code | The service-role key is referenced only by server configuration and is absent from `public/`; `.env` is ignored by Git. | Local file review verified: `public/` contains zero references to `service_role` key. | Scan git commit history before final submission. Rotate keys if exposed. |
| Uploaded file uses a misleading filename or MIME header | File content signature is detected using magic bytes (`file-type`); only PDF/PNG/JPEG signatures are accepted; storage object names are random. | **Implemented, locally checked:** Automated tests verify that spoofed MIME/text files are rejected with 415, and valid PNG/PDF files are accepted. | Test oversize files and malformed image headers against live Supabase Storage. |
| Private document is exposed using a public Storage URL | Application expects a private bucket; downloads go through the backend, which checks current access before fetching bytes. | Requires Supabase configuration. | Verify bucket privacy and test that direct unauthenticated storage URLs cannot read objects. |
| Audit records are changed or deleted through the application | No audit update/delete endpoint is exposed. The migration adds a trigger rejecting row updates/deletes and enables RLS without client policies. | Migration inspected. Trigger defined in `001_schema.sql`. | Test attempted direct SQL UPDATE/DELETE against live disposable Supabase database. |
| Audit storage becomes unavailable | Audit writes throw errors, so operations relying on confirmed logging return an error; denied requests remain denied. | Code inspected; non-UUID probe logging sanitized to prevent type crash in audit table. | Add chaos/mock injection test for database connection drop during audit insertion. |
| Cross-site request causes changes using a stolen/open browser session | Cookies are HttpOnly and SameSite=Strict; unsafe methods also require the configured Origin. | Middleware implemented (`csrf.js`). | Test with live browser origin and verify HTTPS headers in production. |
| Login brute force | The login endpoint is rate-limited (10 requests per 15 min via `express-rate-limit`). | Code inspection verified. | Verify 429 response under load in production. |
| User attempts to view the admin audit endpoint | The backend requires the `administrator` role and records denied attempts. | **Implemented, locally checked:** Automated route tests verify that document owners and viewers receive 403 Forbidden, and denial is logged; admins receive 200 OK. | Verify against live Supabase admin profile. |
| Search query tries to inject SQL | Queries are built using Supabase/PostgREST parameter APIs; search inputs are length-limited and punctuation sanitized. | Helper tests cover normalization and length truncation. | Run query fuzzing against live database. |
| A storage or database mutation succeeds but a later audit write fails | Mutating operations write an attempt event before action and a success event afterwards. Fixed: `PATCH /:id` avoids deleting committed storage file if audit fails. | Fixed in code; partial-failure paths identified. | Document remaining limitations (lack of distributed 2PC transaction between Supabase Storage and Postgres). |

## Priority tests before submission

1. Create owner A, viewer B and a document owned by A. Prove B receives 403 for metadata, download, edit, delete and permission-management calls before a grant.
2. Grant B read access. Prove B can download but cannot edit, delete, grant or revoke.
3. Revoke B's grant. Prove B's next request is denied.
4. Grant edit access. Prove B can change allowed metadata/replace a valid file but still cannot manage permissions or delete the document.
5. Attempt to use the Supabase Storage endpoint without authorization; it must not expose the object.
6. Confirm an ordinary user cannot query or mutate audit records directly, and that UPDATE/DELETE are rejected by the trigger.
7. Try non-admin `/api/admin/audit` access and confirm 403.
8. Test malformed, spoofed and oversized file uploads.
9. Test audit-database failure and storage failure to identify and document partial operations.

Do not change a status to verified until the relevant test has actually run and its output has been reviewed.
