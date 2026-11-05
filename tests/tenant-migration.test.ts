import assert from 'node:assert/strict';
import { test } from 'node:test';
import Database from 'better-sqlite3';
import { migrateTenantFoundation } from '../db/migrations.ts';

function createLegacySchema(db: InstanceType<typeof Database>): void {
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE classes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);
    CREATE TABLE class_teachers (
      class_id INTEGER NOT NULL REFERENCES classes(id),
      teacher_id INTEGER NOT NULL REFERENCES users(id),
      PRIMARY KEY(class_id,teacher_id)
    );
    CREATE TABLE class_students (
      class_id INTEGER NOT NULL REFERENCES classes(id),
      student_id INTEGER NOT NULL REFERENCES users(id),
      PRIMARY KEY(class_id,student_id)
    );
    CREATE TABLE assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      created_by INTEGER NOT NULL REFERENCES users(id)
    );
    CREATE TABLE assignment_classes (
      assignment_id INTEGER NOT NULL REFERENCES assignments(id),
      class_id INTEGER NOT NULL REFERENCES classes(id),
      PRIMARY KEY(assignment_id,class_id)
    );
    CREATE TABLE submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assignment_id INTEGER NOT NULL REFERENCES assignments(id),
      student_id INTEGER NOT NULL REFERENCES users(id)
    );
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submission_id INTEGER NOT NULL REFERENCES submissions(id),
      teacher_id INTEGER REFERENCES users(id)
    );
    CREATE TABLE audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER REFERENCES users(id)
    );
    CREATE TABLE sessions (
      jti TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id)
    );
  `);
}

test('tenant foundation migration preserves and maps existing school data idempotently', () => {
  const db = new Database(':memory:');
  try {
    createLegacySchema(db);
    db.prepare('INSERT INTO users(email,role) VALUES(?,?)').run('admin@school.example','admin');
    db.prepare('INSERT INTO users(email,role) VALUES(?,?)').run('teacher@school.example','teacher');
    db.prepare('INSERT INTO users(email,role) VALUES(?,?)').run('student@school.example','student');
    db.prepare('INSERT INTO classes(name) VALUES(?)').run('Class A');
    db.prepare('INSERT INTO class_teachers(class_id,teacher_id) VALUES(1,2)').run();
    db.prepare('INSERT INTO class_students(class_id,student_id) VALUES(1,3)').run();
    db.prepare('INSERT INTO assignments(title,created_by) VALUES(?,?)').run('Assignment A',2);
    db.prepare('INSERT INTO assignment_classes(assignment_id,class_id) VALUES(1,1)').run();
    db.prepare('INSERT INTO submissions(assignment_id,student_id) VALUES(1,3)').run();
    db.prepare('INSERT INTO feedback(submission_id) VALUES(1)').run();
    db.prepare('INSERT INTO audit_logs(actor_id) VALUES(2)').run();
    db.prepare('INSERT INTO sessions(jti,user_id) VALUES(?,?)').run('session-a',3);

    migrateTenantFoundation(db,false);

    const organization = db.prepare('SELECT id,slug FROM organizations').get() as {id:number;slug:string};
    assert.equal(organization.slug,'legacy-learnora');
    const memberships = db.prepare('SELECT user_id,role,organization_id FROM organization_memberships ORDER BY user_id')
      .all() as Array<{user_id:number;role:string;organization_id:number}>;
    assert.deepEqual(memberships.map(({user_id,role})=>[user_id,role]),[
      [1,'org_admin'],[2,'teacher'],[3,'student'],
    ]);
    assert.ok(memberships.every((membership)=>membership.organization_id===organization.id));
    for (const table of ['classes','class_teachers','class_students','assignments','assignment_classes','submissions','feedback','audit_logs']) {
      const row=db.prepare(`SELECT organization_id FROM ${table} LIMIT 1`).get() as {organization_id:number};
      assert.equal(row.organization_id,organization.id,`${table} should be assigned to the legacy organisation`);
    }
    assert.equal((db.prepare('SELECT active_organization_id FROM sessions WHERE jti=?').get('session-a') as {active_organization_id:number}).active_organization_id,organization.id);
    assert.equal((db.prepare('SELECT is_platform_admin FROM users WHERE id=1').get() as {is_platform_admin:number}).is_platform_admin,0);
    assert.equal((db.prepare('SELECT version FROM schema_migrations').get() as {version:number}).version,1);

    const otherOrganizationId = Number(db.prepare("INSERT INTO organizations(slug,display_name) VALUES('other-school','Other School')").run().lastInsertRowid);
    db.prepare('INSERT INTO classes(name,organization_id) VALUES(?,?)').run('Class B',otherOrganizationId);
    const noTenantWrites: Array<[string, () => unknown]> = [
      ['classes insert', () => db.prepare('INSERT INTO classes(name) VALUES(?)').run('Missing tenant class')],
      ['class_teachers insert', () => db.prepare('INSERT INTO class_teachers(class_id,teacher_id) VALUES(1,1)').run()],
      ['class_students insert', () => db.prepare('INSERT INTO class_students(class_id,student_id) VALUES(1,1)').run()],
      ['assignments insert', () => db.prepare('INSERT INTO assignments(title,created_by) VALUES(?,?)').run('Missing tenant assignment',2)],
      ['assignment_classes insert', () => db.prepare('INSERT INTO assignment_classes(assignment_id,class_id) VALUES(1,2)').run()],
      ['submissions insert', () => db.prepare('INSERT INTO submissions(assignment_id,student_id) VALUES(1,1)').run()],
      ['feedback insert', () => db.prepare('INSERT INTO feedback(submission_id) VALUES(1)').run()],
      ['classes update', () => db.prepare('UPDATE classes SET organization_id=NULL WHERE id=1').run()],
    ];
    for (const [table,write] of noTenantWrites) {
      assert.throws(write,/organization_id is required/,
        `the database must reject tenantless ${table}`);
    }
    assert.throws(
      () => db.prepare('INSERT INTO sessions(jti,user_id) VALUES(?,?)').run('ordinary-session-without-tenant',3),
      /active organization is required/,
      'ordinary user sessions must have an active organisation',
    );
    assert.throws(
      () => db.prepare('INSERT INTO assignment_classes(assignment_id,class_id,organization_id) VALUES(1,2,?)').run(otherOrganizationId),
      /same organisation/,
      'database trigger should reject cross-organisation assignment links',
    );
    assert.throws(
      () => db.prepare('INSERT INTO sessions(jti,user_id,active_organization_id) VALUES(?,?,?)').run('invalid-session',3,otherOrganizationId),
      /active membership/,
      'database trigger should reject a session without an active tenant membership',
    );

    migrateTenantFoundation(db,false);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organizations').get() as {count:number}).count),2);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organization_memberships').get() as {count:number}).count),3);
  } finally {
    db.close();
  }
});

test('tenant migration rolls back every schema change after a precondition failure', () => {
  const db = new Database(':memory:');
  try {
    createLegacySchema(db);
    db.exec(`
      CREATE TABLE organizations (
        id INTEGER PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        settings_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO organizations(slug,display_name) VALUES('school-a','School A');
      INSERT INTO organizations(slug,display_name) VALUES('school-b','School B');
    `);
    db.prepare('INSERT INTO users(email,role) VALUES(?,?)').run('teacher@school.example','teacher');
    db.prepare('INSERT INTO classes(name) VALUES(?)').run('Preserved class');

    assert.throws(
      () => migrateTenantFoundation(db,false),
      /requires explicit mapping/,
      'ambiguous existing organisations must stop the migration',
    );

    const hasColumn = (table:string,column:string) =>
      (db.pragma(`table_info(${table})`) as Array<{name:string}>).some((item)=>item.name===column);
    assert.equal(hasColumn('users','is_platform_admin'),false,'user columns must roll back');
    assert.equal(hasColumn('classes','organization_id'),false,'tenant columns must roll back');
    assert.equal(hasColumn('assignments','organization_id'),false,'all table alterations must roll back');
    assert.equal(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='organization_memberships'").get(),undefined,
      'new membership tables must roll back');
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM schema_migrations').get() as {count:number}).count),0,
      'the failed migration must not be marked as applied');
    assert.equal((db.prepare('SELECT name FROM classes').get() as {name:string}).name,'Preserved class',
      'pre-existing data must remain intact');
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organizations').get() as {count:number}).count),2,
      'pre-existing organisations must remain intact');
  } finally {
    db.close();
  }
});

test('empty production database does not get a demo organisation', () => {
  const db = new Database(':memory:');
  try {
    createLegacySchema(db);
    migrateTenantFoundation(db,true);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organizations').get() as {count:number}).count),0);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organization_memberships').get() as {count:number}).count),0);
    assert.equal((db.prepare('SELECT version FROM schema_migrations').get() as {version:number}).version,1);
  } finally {
    db.close();
  }
});
