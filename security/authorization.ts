type AuthorizationDb = {
  prepare: (sql: string) => {
    get: (...params: number[]) => unknown;
  };
};

type AuthorizationUser = {
  id: number;
  role: 'admin' | 'teacher' | 'student';
};

/**
 * Checks access to a single submission.
 *
 * A teacher must teach the same class the submitting student belongs to,
 * and that class must be linked to the assignment. Assignment-level access
 * alone is not sufficient when an assignment is shared between classes.
 */
export function canSeeSubmission(
  db: AuthorizationDb,
  user: AuthorizationUser,
  submissionId: number
): boolean {
  if (user.role === 'admin') {
    return Boolean(
      db.prepare('SELECT 1 FROM submissions WHERE id = ?').get(submissionId)
    );
  }

  if (user.role === 'student') {
    return Boolean(
      db.prepare('SELECT 1 FROM submissions WHERE id = ? AND student_id = ?')
        .get(submissionId, user.id)
    );
  }

  return Boolean(
    db.prepare(`
      SELECT 1
      FROM submissions s
      INNER JOIN assignment_classes ac
        ON ac.assignment_id = s.assignment_id
      INNER JOIN class_students cs
        ON cs.class_id = ac.class_id
       AND cs.student_id = s.student_id
      INNER JOIN class_teachers ct
        ON ct.class_id = ac.class_id
       AND ct.teacher_id = ?
      WHERE s.id = ?
      LIMIT 1
    `).get(user.id, submissionId)
  );
}
