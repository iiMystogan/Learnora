import assert from 'node:assert/strict';
import { test } from 'node:test';
import Database from 'better-sqlite3';
import { canDeleteAssignment, canSeeSubmission, canSubmitAssignment } from '../security/authorization.ts';

test('submission authorization is scoped to the teacher and student shared class', () => {
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


test('teachers can delete only assignments exclusive to their own classes', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE assignments (id INTEGER PRIMARY KEY);
    CREATE TABLE assignment_classes (assignment_id INTEGER NOT NULL, class_id INTEGER NOT NULL);
    CREATE TABLE class_teachers (class_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL);

    INSERT INTO assignments VALUES (50), (51), (52), (53);
    INSERT INTO assignment_classes VALUES (50, 1);
    INSERT INTO assignment_classes VALUES (51, 1), (51, 2);
    INSERT INTO assignment_classes VALUES (52, 2);
    INSERT INTO assignment_classes VALUES (53, 1);
    INSERT INTO class_teachers VALUES (1, 10), (2, 20);
  `);

  try {
    assert.equal(canDeleteAssignment(db, { id: 10, role: 'teacher' }, 50), true,
      'teacher can delete an assignment linked only to their own class');
    assert.equal(canDeleteAssignment(db, { id: 10, role: 'teacher' }, 51), false,
      'teacher cannot delete an assignment shared with another teacher class');
    assert.equal(canDeleteAssignment(db, { id: 10, role: 'teacher' }, 52), false,
      'teacher cannot delete an assignment linked only to another teacher class');
    assert.equal(canDeleteAssignment(db, { id: 10, role: 'teacher' }, 999), false,
      'teacher cannot delete a non-existent assignment');
    assert.equal(canDeleteAssignment(db, { id: 1, role: 'admin' }, 51), true,
      'admin can delete an existing assignment shared across classes');
    assert.equal(canDeleteAssignment(db, { id: 1, role: 'admin' }, 999), false,
      'admin cannot delete a non-existent assignment');
    assert.equal(canDeleteAssignment(db, { id: 201, role: 'student' }, 50), false,
      'students cannot delete assignments');
  } finally {
    db.close();
  }
});


test('students can submit only to published assignments in their own classes', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE assignments (id INTEGER PRIMARY KEY, status TEXT NOT NULL);
    CREATE TABLE assignment_classes (assignment_id INTEGER NOT NULL, class_id INTEGER NOT NULL);
    CREATE TABLE class_students (class_id INTEGER NOT NULL, student_id INTEGER NOT NULL);

    INSERT INTO assignments VALUES (60, 'published'), (61, 'draft'), (62, 'published');
    INSERT INTO assignment_classes VALUES (60, 1), (61, 1), (62, 2);
    INSERT INTO class_students VALUES (1, 201), (2, 202);
  `);

  try {
    assert.equal(canSubmitAssignment(db, { id: 201, role: 'student' }, 60), true,
      'student can submit to a published assignment in their class');
    assert.equal(canSubmitAssignment(db, { id: 201, role: 'student' }, 61), false,
      'student cannot submit to an unpublished assignment');
    assert.equal(canSubmitAssignment(db, { id: 201, role: 'student' }, 62), false,
      'student cannot submit to an assignment linked only to another class');
    assert.equal(canSubmitAssignment(db, { id: 201, role: 'student' }, 999), false,
      'student cannot submit to a non-existent assignment');
    assert.equal(canSubmitAssignment(db, { id: 10, role: 'teacher' }, 60), false,
      'teachers cannot use the student submission authorization');
  } finally {
    db.close();
  }
});


test('teacher dashboard counts submissions only from students in their own classes', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE assignments (id INTEGER PRIMARY KEY, title TEXT, created_at TEXT);
    CREATE TABLE assignment_classes (assignment_id INTEGER NOT NULL, class_id INTEGER NOT NULL);
    CREATE TABLE class_teachers (class_id INTEGER NOT NULL, teacher_id INTEGER NOT NULL);
    CREATE TABLE class_students (class_id INTEGER NOT NULL, student_id INTEGER NOT NULL);
    CREATE TABLE submissions (id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL, student_id INTEGER NOT NULL);

    INSERT INTO assignments VALUES (70, 'Shared assignment', '2026-11-03');
    INSERT INTO assignment_classes VALUES (70, 1), (70, 2);
    INSERT INTO class_teachers VALUES (1, 10), (2, 20);
    INSERT INTO class_students VALUES (1, 201), (2, 202);
    INSERT INTO submissions VALUES (301, 70, 201), (302, 70, 202);
  `);

  try {
    const rows = db.prepare(`
      SELECT a.id, COUNT(DISTINCT s.id) AS submission_count
      FROM assignments a
      JOIN assignment_classes ac ON ac.assignment_id=a.id
      JOIN class_teachers ct ON ct.class_id=ac.class_id
      LEFT JOIN submissions s ON s.assignment_id=a.id
        AND EXISTS (
          SELECT 1 FROM class_students csx
          WHERE csx.class_id=ac.class_id AND csx.student_id=s.student_id
        )
      WHERE ct.teacher_id=?
      GROUP BY a.id
    `).all(10) as Array<{id:number;submission_count:number}>;

    assert.deepEqual(rows, [{id:70,submission_count:1}],
      'teacher dashboard must not count submissions from another teacher class');
  } finally {
    db.close();
  }
});
