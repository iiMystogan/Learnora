import type Database from 'better-sqlite3';

type MigrationDatabase = InstanceType<typeof Database>;

const tenantColumns: Array<[string, string]> = [
  ['classes', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['class_teachers', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['class_students', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['assignments', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['assignment_classes', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['submissions', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['feedback', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['audit_logs', 'organization_id INTEGER REFERENCES organizations(id)'],
  ['sessions', 'active_organization_id INTEGER REFERENCES organizations(id)'],
];

const columnExists = (db: MigrationDatabase, table: string, column: string): boolean =>
  (db.pragma(`table_info(${table})`) as Array<{ name: string }>).some((item) => item.name === column);

const addColumnIfMissing = (db: MigrationDatabase, table: string, definition: string): void => {
  const column = definition.split(' ', 1)[0];
  if (!columnExists(db, table, column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
};

const countRows = (db: MigrationDatabase, table: string): number =>
  Number((db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count);

/**
 * Adds the organisation and membership foundation to the existing single-school
 * schema. This migration only backfills the tenant key; route enforcement and
 * same-tenant composite constraints are separate follow-up steps.
 */
export function migrateTenantFoundation(db: MigrationDatabase, isProduction: boolean): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const currentVersion = Number((db.prepare('SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations').get() as { version: number }).version);
  if (currentVersion >= 1) return;

  const migrate = db.transaction(() => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
        settings_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS organization_memberships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('org_admin','teacher','student')),
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(organization_id,user_id)
      );
    `);

    addColumnIfMissing(db, 'users', 'is_platform_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_platform_admin IN (0,1))');
    for (const [table, definition] of tenantColumns) addColumnIfMissing(db, table, definition);

    const existingOrganizations = db.prepare('SELECT id FROM organizations ORDER BY id').all() as Array<{ id: number }>;
    if (existingOrganizations.length > 1) {
      throw new Error('Tenant foundation migration requires explicit mapping when multiple organisations already exist.');
    }

    let organizationId: number | null = existingOrganizations[0]?.id ?? null;
    const hasExistingSchoolData = ['users','classes','assignments','submissions'].some((table) => countRows(db, table) > 0);
    const demoAccountCount = Number((db.prepare("SELECT COUNT(*) AS count FROM users WHERE email LIKE '%@demo.local'").get() as {count:number}).count);
    const isLocalDemoDataset = !isProduction && demoAccountCount > 0;
    if (organizationId === null && (hasExistingSchoolData || !isProduction)) {
      const slug = isLocalDemoDataset ? 'learnora-demo' : 'legacy-learnora';
      const displayName = isLocalDemoDataset ? 'Learnora Demo School' : 'Imported Learnora Organisation';
      organizationId = Number(db.prepare('INSERT INTO organizations(slug,display_name) VALUES(?,?)')
        .run(slug, displayName).lastInsertRowid);
    }

    if (organizationId !== null) {
      db.prepare(`
        INSERT OR IGNORE INTO organization_memberships(organization_id,user_id,role,active)
        SELECT ?,id,
          CASE WHEN role='admin' THEN 'org_admin' ELSE role END,
          active
        FROM users
        WHERE is_platform_admin=0
      `).run(organizationId);

      db.prepare('UPDATE classes SET organization_id=? WHERE organization_id IS NULL').run(organizationId);
      db.prepare('UPDATE assignments SET organization_id=? WHERE organization_id IS NULL').run(organizationId);
      db.prepare(`UPDATE class_teachers SET organization_id=(
        SELECT c.organization_id FROM classes c WHERE c.id=class_teachers.class_id
      ) WHERE organization_id IS NULL`).run();
      db.prepare(`UPDATE class_students SET organization_id=(
        SELECT c.organization_id FROM classes c WHERE c.id=class_students.class_id
      ) WHERE organization_id IS NULL`).run();
      db.prepare(`UPDATE assignment_classes SET organization_id=(
        SELECT a.organization_id FROM assignments a WHERE a.id=assignment_classes.assignment_id
      ) WHERE organization_id IS NULL`).run();
      db.prepare(`UPDATE submissions SET organization_id=(
        SELECT a.organization_id FROM assignments a WHERE a.id=submissions.assignment_id
      ) WHERE organization_id IS NULL`).run();
      db.prepare(`UPDATE feedback SET organization_id=(
        SELECT s.organization_id FROM submissions s WHERE s.id=feedback.submission_id
      ) WHERE organization_id IS NULL`).run();
      db.prepare(`UPDATE audit_logs SET organization_id=(
        SELECT m.organization_id FROM organization_memberships m WHERE m.user_id=audit_logs.actor_id LIMIT 1
      ) WHERE organization_id IS NULL AND actor_id IS NOT NULL`).run();
      db.prepare(`UPDATE sessions SET active_organization_id=(
        SELECT m.organization_id FROM organization_memberships m WHERE m.user_id=sessions.user_id LIMIT 1
      ) WHERE active_organization_id IS NULL`).run();
    }

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_memberships_org_user ON organization_memberships(organization_id,user_id);
      CREATE INDEX IF NOT EXISTS idx_classes_organization ON classes(organization_id);
      CREATE INDEX IF NOT EXISTS idx_assignments_organization ON assignments(organization_id);
      CREATE INDEX IF NOT EXISTS idx_submissions_organization ON submissions(organization_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_organization ON audit_logs(organization_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_active_organization ON sessions(active_organization_id);
    `);

    db.prepare('INSERT INTO schema_migrations(version,name) VALUES(?,?)').run(1, 'tenant_foundation');
  });

  migrate();
}
