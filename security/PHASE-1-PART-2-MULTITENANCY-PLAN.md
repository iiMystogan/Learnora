# Phase 1 – Part 2: multi-tenancy assessment

Status: **Phase 1 – Part 2 implementation complete on the separate security branch. The persistent database has not been migrated; use the documented backup and restore procedure before any deployment.**

## Why Part 2 is needed

The product roadmap makes Learnora a service for multiple independent schools. The current data model has no organisation entity or organisation key. A user from one school therefore cannot yet be separated from every other school's records by a tenant boundary. Multi-tenancy is a prerequisite for serving independent organisations and for the later Phase 2 product work.

## Current inventory on `security/phase-1-backend`

The SQLite schema includes `organizations`, `organization_memberships`, tenant ID columns, and an active organisation ID on sessions. A versioned migration backfills legacy/demo data. Database triggers reject missing tenant IDs and cross-organisation links. Authenticated data APIs scope reads and writes to the server-validated active organisation; membership roles drive authorization.

## Tenant ownership and role decisions for v1

1. Keep one global user identity and allow it to have memberships in multiple organisations. This supports staff who work with more than one school and avoids duplicate local identities for the same email.
2. Store `org_admin`, `teacher`, and `student` roles on an organisation-membership record, not on the global user. A user's role can differ between organisations.
3. Keep central platform administration as a separate global capability. Platform administrators receive no school membership by default and no automatic access to school work. Each platform action that targets an organisation must name and audit that organisation.
4. Bind each ordinary session to one active organisation membership. The server loads that membership; it never accepts an organisation ID from request data as proof of access. Switching organisations requires the server to verify another active membership.
5. Store organisation IDs on organisation-owned records and enforce same-organisation relationships with database triggers and uniqueness constraints. Tenant IDs are required for school-owned writes; platform sessions may remain unbound.

This is the initial product model based on the roadmap's separate organisations and organisation-specific roles. Entra ID identity mapping remains a later authentication step.

## Proposed schema shape

- `organizations`: stable ID, unique short name/slug, display name, status, and organisation-specific settings/branding.
- `users`: global identity and authentication fields, unique local email, active status, and a separate platform-administrator flag/capability.
- `organization_memberships`: organisation ID, user ID, organisation-scoped role and active status, unique per organisation/user.
- `classes`, `assignments`, `assignment_classes`, `class_teachers`, `class_students`, `submissions`, `feedback`, and `audit_logs`: tenant ownership keys plus same-tenant constraints.
- `sessions`: user ID and active organisation membership/context; platform sessions without a school context remain explicitly platform-scoped.
- `login_rate_limits`: remain global unless later threat analysis supports tenant-scoped limits.

The additive SQLite migration, indexes, strict tenant triggers, and route enforcement are implemented. Cross-tenant integration coverage exercises the main routes and roles, including attempts to override the tenant ID.

## Existing data migration

Use a versioned, transactional migration. Existing demo data should be assigned to one synthetic organisation. The existing `admin@demo.local` account becomes an `org_admin` membership, not a platform administrator. Production migrations must not create demo accounts or organisations. Provisioning any platform administrator must be an explicit, controlled operation. A backup and rollback procedure is required before applying a migration to a persistent environment.

## Migration safety and rollback

The tenant migration applies its schema and data changes in one SQLite transaction. The schema-version table is created before that transaction; a failed run can therefore leave the empty version table, but must not leave partial tenant tables, columns, backfills, or a recorded migration version. A regression test forces the ambiguous-organisation precondition to fail and checks that the transaction restores the original schema and data.

Before applying the migration to a persistent database:

1. Put the application in maintenance mode and stop writes.
2. Create a consistent SQLite backup and a matching backup of any files needed to keep the environment recoverable. Verify the backup by restoring it to a temporary database and checking its integrity and foreign keys.
3. Start the updated application and confirm the migration version, tenant counts, and foreign-key checks before reopening access.

If the migration aborts, its transaction rolls back and the issue can be corrected before retrying. If a successful migration must be reversed before accepting new writes, restore the verified pre-migration backup. Do not run an automatic down migration: once tenant-scoped writes have occurred, removing tenant fields or restoring an older database could discard those writes. After writes resume, prefer a forward repair or reconcile new data before any restore.

## Step-by-step implementation sequence

1. Tenant ownership and role rules: **complete** (decisions above).
2. Design and implement a schema-version mechanism and additive migration that creates the organisation and membership model without dropping existing data: **complete**.
3. Add database constraints for same-organisation class, assignment, submission, feedback, and membership relationships: **complete; database triggers reject cross-organisation links and missing tenant IDs, and ordinary sessions require an active organisation**.
4. Add a trusted active-organisation context to authentication and authorization helpers: **complete; session organisation is loaded from the database and checked against an active membership**.
5. Scope API reads and writes, then uploads/downloads, to that context: **complete across dashboards, classes, assignments, submissions, feedback, downloads, and organisation administration**.
6. Add cross-tenant integration tests for every endpoint and role, including attempts to alter tenant IDs in request data: **complete for class, dashboard, assignment, submission, feedback, upload/download, and organisation-administration boundaries across students, teachers, and organisation administrators**.
7. Verify migration, rollback, TypeScript, build, dependency audit, and full regression checks on the separate branch: **complete; rollback atomicity test and backup/restore runbook added, and all CI checks passed**.

## Deliberately deferred

No Entra ID integration, PostgreSQL move, object-storage move, production deployment, ICT demonstration, or Phase 2 feature work is included here. Those remain later steps in the agreed project order.
