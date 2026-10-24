# TrustVault — interview learning notes

Use this as a study guide. Only claim behavior as verified after you have run the relevant tests and checked the deployed configuration.

## Architecture in one minute

The browser sends same-origin requests to an Express backend. Login is handled through Supabase Auth. The server sets HttpOnly cookies so browser JavaScript cannot read session tokens. For protected routes, the backend verifies the token, loads the user's profile and role from PostgreSQL, loads the requested document, and checks ownership or an explicit permission grant. Document files are held in a private Supabase Storage bucket; the backend fetches and returns the file only after authorization succeeds.

## Questions to practise

### What is authentication versus authorization?
Authentication verifies identity (who signed in). Authorization checks whether that identity can perform a particular action on a particular resource.

### Why is a UI-only permission check insufficient?
A user can call an API directly, edit browser JavaScript, or change a document ID. Therefore, each protected API route must enforce authorization on the server.

### What is IDOR?
Insecure Direct Object Reference is a class of access-control flaw where changing an object identifier allows a user to reach an object they are not entitled to see. UUIDs make guessing harder but do not replace permission checks.

### Why do edit grants imply read access?
Editing a document without being able to read what is being changed is not useful. The access-decision helper deliberately treats `can_edit` as also granting `can_read`; permission management remains separate.

### What does immediate revocation mean here?
Each request reloads the current grant from the database rather than relying on a cached authorization decision or giving the browser a long-lived signed URL. An already downloaded copy cannot be recalled; revocation blocks later requests.

### How does the audit trail work?
The server appends events with actor, role, action, outcome, document ID, time, IP and limited details. The application exposes no audit edit/delete endpoint and the migration rejects row-level updates/deletes with a trigger. This is tamper-resistant against ordinary application operations, not absolutely immutable against a database owner who can alter schema objects.

### What is not proven yet?
This starter contains local unit tests but has not yet been tested against live Supabase or a deployed Render service. Until integration tests are run, route-level authorization, Storage bucket privacy, deployment cookie settings, and failure scenarios must be described as unverified.
