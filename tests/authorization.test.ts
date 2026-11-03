import assert from 'node:assert/strict';
import testCase from 'node:test';
import Database from 'better-sqlite3';
import { canSeeSubmission } from '../security/authorization.ts';

testCase('submission authorization is scoped to the teacher and student shared class', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE submissions (
      id INTEGER PRIMARY KEY,
      assignment_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL
    );
    CREATE TABLE assignment_classes (
      assignment_id INTEGER NOT NULL,
      class_id INTEGER NOT NULL
    );
    CREATE TABLE class_students (
      class_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL
    );
    CREATE TABLE class_teachers (
      class_id INTEGER NOT NULL,
      teacher_id INTEGER NOT NULL
    );

    INSERT INTO submissions VALUES (101, 50, 201);
    INSERT INTO submissions VALUES (102, 50, 202);
    INSERT INTO submissions VALUES (103, 51, 203);

    INSERT INTO assignment_classes VALUES (50, 1);
    INSERT INTO assignment_classes VALUES (50, 2);
    INSERT INTO assignment_classes VALUES (51, 3);

    INSERT INTO class_students VALUES (1, 201);
    INSERT INTO class_students VALUES (2, 202);
    INSERT INTO class_students VALUES (3, 203);

    INSERT INTO class_teachers VALUES (1, 10);
    INSERT INTO class_teachers VALUES (2, 20);
    INSERT INTO class_teachers VALUES (3, 30);
  `);

  try {
    assert.equal(canSeeSubmission(db, { id: 10, role: 'teacher' }, 101), true,
      'teacher can access a student submission in their own class');
    assert.equal(canSeeSubmission(db, { id: 10, role: 'teacher' }, 102), false,
      'teacher cannot access another class submission for a shared assignment');
    assert.equal(canSeeSubmission(db, { id: 20, role: 'teacher' }, 101), false,
      'the other teacher cannot access the first class submission');
    assert.equal(canSeeSubmission(db, { id: 30, role: 'teacher' }, 103), true,
      'teacher can access a submission in their own separate class');
    assert.equal(canSeeSubmission(db, { id: 10, role: 'teacher' }, 999), false,
      'non-existent submissions are denied');

    assert.equal(canSeeSubmission(db, { id: 201, role: 'student' }, 101), true,
      'student can access their own submission');
    assert.equal(canSeeSubmission(db, { id: 201, role: 'student' }, 102), false,
      'student cannot access another student submission');

    assert.equal(canSeeSubmission(db, { id: 1, role: 'admin' }, 102), true,
      'admin can access an existing submission');
    assert.equal(canSeeSubmission(db, { id: 1, role: 'admin' }, 999), false,
      'admin access still requires the submission to exist');
  } finally {
    db.close();
  }
});
