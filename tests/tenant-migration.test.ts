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
      submission_id INTEGER NOT NULL REFERENCES submissions(id)
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

    migrateTenantFoundation(db,false);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organizations').get() as {count:number}).count),1);
    assert.equal(Number((db.prepare('SELECT COUNT(*) AS count FROM organization_memberships').get() as {count:number}).count),3);
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
