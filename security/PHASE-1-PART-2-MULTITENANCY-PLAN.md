# Phase 1 – Part 2: multi-tenancy assessment

Status: **required; design/inventory only**. No tenant schema or route changes have been implemented in this step.

## Why Part 2 is needed

The product roadmap makes Learnora a service for multiple independent schools. The current data model has no organisation entity or organisation key. A user from one school therefore cannot yet be separated from every other school's records by a tenant boundary. Multi-tenancy is a prerequisite for serving independent organisations and for the later Phase 2 product work.

## Current inventory on `security/phase-1-backend`

The SQLite schema contains:

- Identity and access: `users`, `sessions`, `login_rate_limits`.
- School work: `classes`, `class_teachers`, `class_students`, `assignments`, `assignment_classes`, `submissions`, `feedback`.
- Operations: `audit_logs`.

There is no `organizations` table or tenant identifier. The current role constraint is `admin`, `teacher`, or `student`. API authorization scopes teachers and students to classes, but it has no organization boundary to enforce.

## Proposed tenant model

This is the starting design for review before schema implementation:

- Add an `organizations` table with a stable ID, unique short name/slug, display name, status, and organisation-specific settings/branding.
- Add an organization ID to every organisation-owned record: users, classes, assignments, relationship tables, submissions, feedback, and audit logs.
- Keep sessions linked to the user so their tenant context comes from the authenticated identity. Keep login rate limits global unless later threat analysis supports tenant-scoped limits.
- Separate `platform_admin` from `org_admin`, `teacher`, and `student`. Platform administrators manage organisations; organisation administrators remain scoped to one organisation.
- Derive a normal user's tenant from the authenticated database record. Do not trust a client-supplied organization ID as authorization.
- Add composite uniqueness and foreign-key constraints so a class, teacher, student, assignment, submission, or feedback record cannot be linked across organisations even if a route check is missed.
- Scope every list, detail, mutation, download, dashboard, and audit query to the authenticated organisation. Platform-level actions must record the affected organisation.
- Keep authentication-provider changes separate. Entra ID is deferred until the very end per the agreed project order.

## Existing data migration

The schema change will need a versioned, transactional migration. Existing demo data should be assigned to one synthetic organisation. The existing `admin@demo.local` account should be mapped to an organisation-scoped administrator, not silently promoted to the central platform role. Production migrations must not create demo accounts or organisations. A backup and rollback procedure is required before applying any migration to a persistent environment.

## Step-by-step implementation sequence

1. Review and settle tenant ownership and role rules, including whether a person can belong to more than one organisation.
2. Implement a schema-version mechanism and an additive migration that creates the organisation and adds tenant keys without dropping existing data.
3. Add database constraints for same-organisation class, assignment, submission, feedback, and membership relationships.
4. Add a trusted tenant context to authentication and authorization helpers.
5. Scope API reads and writes, then uploads/downloads, to that context.
6. Add cross-tenant integration tests for every endpoint and role, including attempts to alter tenant IDs in request data.
7. Verify migration, rollback, TypeScript, build, dependency audit, and full regression checks on the separate branch.

## Deliberately not part of this step

No code/schema migration, Entra ID integration, PostgreSQL move, object-storage move, production deployment, ICT demonstration, or Phase 2 feature work is included here. Those need their own reviewed steps in the agreed order.
