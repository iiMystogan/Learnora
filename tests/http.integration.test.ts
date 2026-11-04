import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import Database from 'better-sqlite3';

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function getFreePort(): Promise<number> {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Could not allocate a test port.');
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForApi(baseUrl: string, child: ChildProcess, getOutput: () => string): Promise<void> {
  const deadline = Date.now() + 30_000;
  let lastError = '';
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Test server exited early (code ${child.exitCode}).\n${getOutput()}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/me`);
      if (response.status === 401) return;
      lastError = `Unexpected readiness status: ${response.status}`;
    } catch (error) {
      lastError = String(error);
    }
    await wait(250);
  }
  throw new Error(`Test server did not become ready: ${lastError}\n${getOutput()}`);
}

test('HTTP authorization boundaries for admin, teachers and students', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'learnora-http-'));
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const output: string[] = [];
  const cliPath = path.join(process.cwd(), 'node_modules', 'tsx', 'dist', 'cli.mjs');
  const child = spawn(process.execPath, [cliPath, 'server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: String(port),
      DATABASE_PATH: path.join(tempDir, 'test.sqlite'),
      UPLOAD_DIR: path.join(tempDir, 'uploads'),
      JWT_SECRET: 'http-integration-test-secret-at-least-32-characters',
      TRUSTED_CLIENT_IP_HEADER: 'x-real-ip',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (chunk) => output.push(String(chunk)));
  child.stderr?.on('data', (chunk) => output.push(String(chunk)));
  const getOutput = () => output.join('');

  const csrf = { token: '', cookie: '' };
  const fetchWithCsrf = (url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    const method = (init.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const cookieHeader = headers.get('Cookie') || '';
      if (!cookieHeader.split(';').some((part) => part.trim().startsWith('learnora_csrf='))) {
        headers.set('Cookie', [cookieHeader, csrf.cookie].filter(Boolean).join('; '));
      }
      headers.set('X-CSRF-Token', csrf.token);
    }
    return fetch(url, { ...init, headers });
  };

  const request = async (
    route: string,
    options: { method?: string; cookie?: string; body?: unknown; csrf?: boolean; csrfToken?: string } = {},
  ) => {
    const headers: Record<string, string> = {};
    let body: BodyInit | undefined;
    const method = (options.method || 'GET').toUpperCase();
    const cookieParts = [options.cookie, csrf.cookie].filter(Boolean);
    if (cookieParts.length) headers.Cookie = cookieParts.join('; ');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && options.csrf !== false) {
      headers['X-CSRF-Token'] = options.csrfToken ?? csrf.token;
    }
    if (options.body instanceof FormData) {
      body = options.body;
    } else if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.body);
    }
    return fetch(`${baseUrl}${route}`, {
      method,
      headers,
      body,
    });
  };

  const login = async (email: string, password: string): Promise<string> => {
    const response = await request('/api/login', {
      method: 'POST',
      body: { email, password },
    });
    assert.equal(response.status, 200, `login should succeed for ${email}`);
    const setCookie = response.headers.get('set-cookie');
    assert.ok(setCookie, 'login must issue a session cookie');
    return setCookie.split(';', 1)[0];
  };

  try {
    await waitForApi(baseUrl, child, getOutput);

    const csrfResponse = await fetchWithCsrf(`${baseUrl}/api/csrf`);
    assert.equal(csrfResponse.status, 200, 'the CSRF bootstrap endpoint must be available');
    csrf.token = ((await csrfResponse.json()) as { csrfToken: string }).csrfToken;
    const csrfCookie = csrfResponse.headers.get('set-cookie');
    assert.ok(csrfCookie, 'CSRF bootstrap must issue a cookie');
    csrf.cookie = csrfCookie.split(';', 1)[0];
    assert.match(csrfCookie, /SameSite=Lax/i);
    assert.doesNotMatch(csrfCookie, /HttpOnly/i, 'the CSRF cookie must be readable by the frontend');

    // Browser security headers must be present on API responses as well as the frontend.
    assert.equal(csrfResponse.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(csrfResponse.headers.get('x-frame-options'), 'DENY');
    assert.equal(csrfResponse.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.equal(csrfResponse.headers.get('permissions-policy'), 'camera=(), microphone=(), geolocation=()');
    const reportOnlyPolicy = csrfResponse.headers.get('content-security-policy-report-only') || '';
    assert.match(reportOnlyPolicy, /default-src 'self'/);
    assert.match(reportOnlyPolicy, /object-src 'none'/);
    assert.match(reportOnlyPolicy, /frame-ancestors 'none'/);
    assert.equal(csrfResponse.headers.has('content-security-policy'), false,
      'CSP must remain report-only until compatibility has been verified');
    assert.equal(csrfResponse.headers.has('strict-transport-security'), false,
      'HSTS is enabled only for production HTTPS deployments');

    // Unsafe requests without the signed header/cookie pair must be rejected.
    assert.equal((await request('/api/login', {
      method: 'POST', csrf: false,
      body: { email: 'admin@demo.local', password: 'Admin123!' },
    })).status, 403);
    assert.equal((await request('/api/login', {
      method: 'POST', csrfToken: 'invalid-token',
      body: { email: 'admin@demo.local', password: 'Admin123!' },
    })).status, 403);

    // Unauthenticated requests must not expose protected resources.
    assert.equal((await request('/api/classes')).status, 401);

    // Authentication endpoints: invalid credentials, current user and logout cookie handling.
    assert.equal((await request('/api/login', { method: 'POST', body: { email: 'admin@demo.local', password: 'incorrect-password' } })).status, 401);
    let admin = await login('admin@demo.local', 'Admin123!');
    const secondAdminSession = await login('admin@demo.local', 'Admin123!');
    const currentUser = await request('/api/me', { cookie: admin });
    assert.equal(currentUser.status, 200);
    assert.equal(((await currentUser.json()) as { user: { role: string } }).user.role, 'admin');
    assert.equal((await request('/api/logout', { method: 'POST', cookie: admin, csrf: false })).status, 403,
      'logout must reject requests without a CSRF token');
    assert.equal((await request('/api/me', { cookie: admin })).status, 200,
      'a rejected logout must leave the session active');
    const logout = await request('/api/logout', { method: 'POST', cookie: admin });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get('set-cookie') || '', /session=;/);
    assert.equal((await request('/api/me')).status, 401);
    assert.equal((await request('/api/me', { cookie: admin })).status, 401,
      'a logged-out JWT must be rejected even when the original cookie is replayed');
    assert.equal((await request('/api/me', { cookie: secondAdminSession })).status, 200,
      'logging out one session must not invalidate another active session');

    // Security-sensitive account changes revoke every session, including after later reactivation.
    const managedUserResponse=await request('/api/admin/users',{method:'POST',cookie:secondAdminSession,body:{
      email:'session.lifecycle@demo.local',displayName:'Session Lifecycle',role:'student',password:'InitialPass123!',
    }});
    assert.equal(managedUserResponse.status,200);
    const managedUserId=(await managedUserResponse.json() as {id:number}).id;
    const managedSessionA=await login('session.lifecycle@demo.local','InitialPass123!');
    const managedSessionB=await login('session.lifecycle@demo.local','InitialPass123!');
    assert.equal((await request(`/api/admin/users/${managedUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{role:'teacher'}})).status,200);
    assert.equal((await request('/api/me',{cookie:managedSessionA})).status,401,'role changes revoke all sessions');
    assert.equal((await request('/api/me',{cookie:managedSessionB})).status,401,'role changes revoke parallel sessions too');
    const afterRoleChange=await login('session.lifecycle@demo.local','InitialPass123!');
    assert.equal((await request(`/api/admin/users/${managedUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{password:'ChangedPass123!'}})).status,200);
    assert.equal((await request('/api/me',{cookie:afterRoleChange})).status,401,'password changes revoke existing sessions');
    assert.equal((await login('session.lifecycle@demo.local','InitialPass123!').catch(()=>'')), '', 'old password must no longer work');
    const afterPasswordChange=await login('session.lifecycle@demo.local','ChangedPass123!');
    assert.equal((await request(`/api/admin/users/${managedUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{active:false}})).status,200);
    assert.equal((await request('/api/me',{cookie:afterPasswordChange})).status,401,'deactivation revokes sessions');
    assert.equal((await request(`/api/admin/users/${managedUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{active:true}})).status,200);
    assert.equal((await request('/api/me',{cookie:afterPasswordChange})).status,401,'reactivation must not revive revoked sessions');
    assert.equal((await request(`/api/admin/users/${managedUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{role:'superuser'}})).status,400);
    assert.equal((await request('/api/admin/users/not-a-number',{method:'PATCH',cookie:secondAdminSession,body:{active:false}})).status,400);
    const adminUserRows=await (await request('/api/admin/users',{cookie:secondAdminSession})).json() as Array<{id:number;email:string}>;
    const adminUserId=adminUserRows.find(item=>item.email==='admin@demo.local')!.id;
    assert.equal((await request(`/api/admin/users/${adminUserId}`,{method:'PATCH',cookie:secondAdminSession,body:{active:false}})).status,400,
      'an administrator cannot deactivate their own account');

    const selfServiceCreate=await request('/api/admin/users',{method:'POST',cookie:secondAdminSession,body:{
      email:'self.change@demo.local',displayName:'Self Service',role:'student',password:'SelfServiceStart123!',
    }});
    assert.equal(selfServiceCreate.status,200);
    const selfServiceSession=await login('self.change@demo.local','SelfServiceStart123!');
    assert.equal((await request('/api/account/password',{method:'POST',cookie:selfServiceSession,body:{
      currentPassword:'wrong-current-password',newPassword:'SelfServiceChanged123!',
    }})).status,400,'self-service change must verify the current password');
    assert.equal((await request('/api/account/password',{method:'POST',cookie:selfServiceSession,body:{
      currentPassword:'SelfServiceStart123!',newPassword:'Short123!xx',
    }})).status,400,'self-service change must enforce the shared password policy');
    assert.equal((await request('/api/account/password',{method:'POST',cookie:selfServiceSession,body:{
      currentPassword:'SelfServiceStart123!',newPassword:'SelfServiceStart123!',
    }})).status,400,'self-service change must reject reusing the current password');
    const selfServiceChange=await request('/api/account/password',{method:'POST',cookie:selfServiceSession,body:{
      currentPassword:'SelfServiceStart123!',newPassword:'SelfServiceChanged123!',
    }});
    assert.equal(selfServiceChange.status,200);
    assert.equal((await selfServiceChange.json() as {reauthenticate:boolean}).reauthenticate,true);
    assert.equal((await request('/api/me',{cookie:selfServiceSession})).status,401,'self-service change revokes the current session');
    assert.equal(await login('self.change@demo.local','SelfServiceStart123!').catch(()=>''),'','the previous password must stop working');
    assert.ok(await login('self.change@demo.local','SelfServiceChanged123!'),'the new password must authenticate');

    admin = await login('admin@demo.local', 'Admin123!');
    const teacherJansen = await login('docent.jansen@demo.local', 'Teacher123!');
    const teacherVisser = await login('docent.visser@demo.local', 'Teacher123!');
    const studentNoor = await login('student.noor@demo.local', 'Student123!');
    const studentSara = await login('student.sara@demo.local', 'Student123!');
    assert.equal((await request('/api/me', { cookie: teacherJansen })).status, 200);
    assert.equal((await request('/api/me', { cookie: studentNoor })).status, 200);

    // Class lists and class detail endpoints must be scoped to the current user.
    const adminClassesResponse = await request('/api/classes', { cookie: admin });
    assert.equal(adminClassesResponse.status, 200);
    const adminClasses = await adminClassesResponse.json() as Array<{ id: number; name: string }>;
    const ictClass = adminClasses.find((item) => item.name === 'ICT 2A');
    const mediaClass = adminClasses.find((item) => item.name === 'Media 3B');
    assert.ok(ictClass && mediaClass, 'demo seed classes should exist');

    const jansenClasses = await (await request('/api/classes', { cookie: teacherJansen })).json() as Array<{ name: string }>;
    assert.deepEqual(jansenClasses.map((item) => item.name), ['ICT 2A']);
    assert.equal((await request(`/api/classes/${mediaClass.id}/students`, { cookie: teacherJansen })).status, 403);

    assert.equal((await request(`/api/classes/${ictClass.id}/students`, { cookie: admin })).status, 200);
    const noorClasses = await (await request('/api/classes', { cookie: studentNoor })).json() as Array<{ name: string }>;
    assert.deepEqual(noorClasses.map((item) => item.name), ['ICT 2A']);
    assert.equal((await request('/api/admin/users', { cookie: teacherJansen })).status, 403);
    assert.equal((await request('/api/admin/overview', { cookie: studentNoor })).status, 403);

    // A teacher cannot create an assignment spanning a class they do not teach.
    assert.equal((await request('/api/assignments', {
      method: 'POST',
      cookie: teacherJansen,
      body: { title: 'Forbidden cross-class assignment', classIds: [ictClass.id, mediaClass.id] },
    })).status, 403);

    // Admin creates a shared assignment so we can test cross-class submission access.
    const createShared = await request('/api/assignments', {
      method: 'POST',
      cookie: admin,
      body: { title: 'HTTP shared-class security test', classIds: [ictClass.id, mediaClass.id] },
    });
    assert.equal(createShared.status, 200);
    const sharedAssignment = await createShared.json() as { id: number };
    assert.equal((await request('/api/assignments', { cookie: admin })).status, 200,
      'admin can list all assignments');
    assert.equal((await request(`/api/assignments/${sharedAssignment.id}/progress`, { cookie: admin })).status, 200,
      'admin can view progress for an existing assignment');
    assert.equal((await request(`/api/assignments/${sharedAssignment.id}/submit`, {
      method: 'POST', cookie: admin, body: new FormData(),
    })).status, 403, 'admin cannot use the student upload endpoint');
    assert.equal((await request(`/api/assignments/${sharedAssignment.id}/submit`, {
      method: 'POST', cookie: teacherJansen, body: new FormData(),
    })).status, 403, 'teacher cannot use the student upload endpoint');

    // Verify the positive and negative write combinations for assignment deletion.
    const teacherOwnedAssignmentResponse = await request('/api/assignments', {
      method: 'POST', cookie: teacherJansen,
      body: { title: 'Teacher-owned authorization test', classIds: [ictClass.id] },
    });
    assert.equal(teacherOwnedAssignmentResponse.status, 200);
    const teacherOwnedAssignment = await teacherOwnedAssignmentResponse.json() as { id: number };
    assert.equal((await request(`/api/assignments/${teacherOwnedAssignment.id}`, {
      method: 'DELETE', cookie: studentNoor,
    })).status, 403, 'student cannot delete an assignment');
    assert.equal((await request(`/api/assignments/${teacherOwnedAssignment.id}`, {
      method: 'DELETE', cookie: teacherJansen,
    })).status, 200, 'teacher can delete an assignment exclusive to their class');
    const adminOwnedAssignmentResponse = await request('/api/assignments', {
      method: 'POST', cookie: admin,
      body: { title: 'Admin-owned authorization test', classIds: [mediaClass.id] },
    });
    assert.equal(adminOwnedAssignmentResponse.status, 200);
    const adminOwnedAssignment = await adminOwnedAssignmentResponse.json() as { id: number };
    assert.equal((await request(`/api/assignments/${adminOwnedAssignment.id}`, {
      method: 'DELETE', cookie: admin,
    })).status, 200, 'admin can delete an existing assignment');

    // Sara belongs to Media 3B. Submit a small PDF through the real multipart upload route.
    const form = new FormData();
    form.append('file', new Blob(['%PDF-1.4\nLearnora HTTP integration test\n'], { type: 'application/pdf' }), 'http-test.pdf');
    const upload = await request(`/api/assignments/${sharedAssignment.id}/submit`, {
      method: 'POST',
      cookie: studentSara,
      body: form,
    });
    assert.equal(upload.status, 200, 'submission upload returned HTTP ' + upload.status);
    const submission = await upload.json() as { id: number };

    // Jansen teaches ICT 2A, not Sara's Media 3B class: no list, feedback or download access.
    const saraSubmissions = await (await request('/api/submissions', { cookie: studentSara })).json() as Array<{ id: number }>;
    assert.equal(saraSubmissions.some((item) => item.id === submission.id), true);
    const noorSubmissions = await (await request('/api/submissions', { cookie: studentNoor })).json() as Array<{ id: number }>;
    assert.equal(noorSubmissions.some((item) => item.id === submission.id), false);
    assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: admin })).status, 200);
    const jansenSubmissions = await (await request('/api/submissions', { cookie: teacherJansen })).json() as Array<{ id: number }>;
    assert.equal(jansenSubmissions.some((item) => item.id === submission.id), false);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: teacherJansen,
      body: { comments: 'Unauthorized feedback', grade: '1' },
    })).status, 404);
    assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: teacherJansen })).status, 403);
    assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: studentNoor })).status, 403);

    // Authorization must follow live class membership and assignment-class links, not stale login state.
    const testDb = new Database(path.join(tempDir, 'test.sqlite'));
    try {
      testDb.prepare('DELETE FROM class_teachers WHERE class_id=? AND teacher_id=?').run(mediaClass.id, 3);
      assert.equal((await request(`/api/classes/${mediaClass.id}/students`, { cookie: teacherVisser })).status, 403,
        'a teacher removed from a class must lose access immediately');
      testDb.prepare('INSERT INTO class_teachers(class_id,teacher_id) VALUES(?,3)').run(mediaClass.id);

      testDb.prepare('DELETE FROM class_students WHERE class_id=? AND student_id=?').run(mediaClass.id, 6);
      const removedStudentSubmissionsResponse = await request('/api/submissions', { cookie: studentSara });
      const removedStudentSubmissions = await removedStudentSubmissionsResponse.json() as Array<{ id: number }>;
      assert.equal(removedStudentSubmissions.some(item => item.id === submission.id), false,
        'a student removed from a class must no longer see class-scoped submission listings');
      const removedStudentAssignmentsResponse = await request('/api/assignments', { cookie: studentSara });
      const removedStudentAssignments = await removedStudentAssignmentsResponse.json() as Array<{ id: number }>;
      assert.equal(removedStudentAssignments.some(item => item.id === sharedAssignment.id), false,
        'a student removed from a class must no longer see its assignments');
      assert.equal((await request(`/api/assignments/${sharedAssignment.id}/submit`, {
        method: 'POST', cookie: studentSara, body: new FormData(),
      })).status, 403, 'a removed student must not submit to the former class assignment');
      testDb.prepare('INSERT INTO class_students(class_id,student_id) VALUES(?,6)').run(mediaClass.id);

      testDb.prepare('DELETE FROM assignment_classes WHERE assignment_id=? AND class_id=?').run(sharedAssignment.id, mediaClass.id);
      const movedStudentAssignments = await (await request('/api/assignments', { cookie: studentSara })).json() as Array<{ id: number }>;
      assert.equal(movedStudentAssignments.some(item => item.id === sharedAssignment.id), false,
        'a student must lose access when an assignment is moved out of their class');
      assert.equal((await request(`/api/assignments/${sharedAssignment.id}/submit`, {
        method: 'POST', cookie: studentSara, body: new FormData(),
      })).status, 403, 'a student cannot submit after an assignment is moved away from their class');
      assert.equal((await request(`/api/assignments/${sharedAssignment.id}/progress`, { cookie: teacherVisser })).status, 404,
        'a teacher must lose assignment access when the assignment is moved away from their class');
      assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: teacherVisser })).status, 403,
        'a teacher must lose access to the submission when its assignment is moved away from their class');
      testDb.prepare('INSERT INTO assignment_classes(assignment_id,class_id) VALUES(?,?)').run(sharedAssignment.id, mediaClass.id);

      // Hold a multipart upload open after authorization passed and the file stream started.
      // Revoke class membership while Multer is still receiving bytes; the post-upload check must reject it.
      const uploadDir = path.join(tempDir, 'uploads');
      const filesBeforeRace = new Set(await readdir(uploadDir));
      const boundary = '----LearnoraAuthorizationRace';
      const encoder = new TextEncoder();
      let uploadController: ReadableStreamDefaultController<Uint8Array> | null = null;
      let signalUploadStarted!: () => void;
      let releaseUpload!: () => void;
      const uploadStarted = new Promise<void>((resolve) => { signalUploadStarted = resolve; });
      const uploadGate = new Promise<void>((resolve) => { releaseUpload = resolve; });
      const streamedBody = new ReadableStream<Uint8Array>({
        start(controller) {
          uploadController = controller;
          controller.enqueue(encoder.encode(
            `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="race.pdf"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4\npartial`,
          ));
          signalUploadStarted();
        },
      });
      const raceUpload = fetchWithCsrf(`${baseUrl}/api/assignments/${sharedAssignment.id}/submit`, {
        method: 'POST',
        headers: {
          Cookie: [studentSara, csrf.cookie].join('; '),
          'X-CSRF-Token': csrf.token,
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
        },
        body: streamedBody,
        duplex: 'half',
      } as RequestInit);
      try {
        await uploadStarted;
        let partialFileWritten = false;
        for (let attempt = 0; attempt < 200; attempt += 1) {
          const currentFiles = await readdir(uploadDir);
          if (currentFiles.some((name) => !filesBeforeRace.has(name))) {
            partialFileWritten = true;
            break;
          }
          await wait(10);
        }
        assert.equal(partialFileWritten, true, 'Multer must be actively receiving the upload before membership changes');
        testDb.prepare('DELETE FROM class_students WHERE class_id=? AND student_id=?').run(mediaClass.id, 6);
        releaseUpload();
        uploadController!.enqueue(encoder.encode(`\r\n--${boundary}--\r\n`));
        uploadController!.close();
        const raceResponse = await raceUpload;
        assert.equal(raceResponse.status, 403,
          'an upload must be rejected when class authorization is revoked while bytes are being received');
      } finally {
        releaseUpload();
      }
      testDb.prepare('INSERT INTO class_students(class_id,student_id) VALUES(?,6)').run(mediaClass.id);
    } finally {
      testDb.close();
    }

    // Visser teaches Media 3B and should be allowed to access Sara's submission.
    const visserSubmissions = await (await request('/api/submissions', { cookie: teacherVisser })).json() as Array<{ id: number }>;
    assert.equal(visserSubmissions.some((item) => item.id === submission.id), true);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: teacherVisser,
      body: { comments: 'Authorized feedback', grade: '8' },
    })).status, 200);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST', cookie: admin, body: { comments: 'Admin feedback', grade: '9' },
    })).status, 200, 'admin can provide feedback on an existing submission');
    const studentDownload = await request(`/api/submissions/${submission.id}/download`, { cookie: studentSara });
    assert.equal(studentDownload.status, 200);
    assert.match(studentDownload.headers.get('content-type') || '', /application\/pdf|application\/octet-stream/);

    // Deleting a shared assignment is destructive for both classes and must be denied to one teacher.
    assert.equal((await request(`/api/assignments/${sharedAssignment.id}`, {
      method: 'DELETE',
      cookie: teacherJansen,
    })).status, 404);
    const stillExists = await (await request('/api/assignments', { cookie: teacherVisser })).json() as Array<{ id: number }>;
    assert.equal(stillExists.some((item) => item.id === sharedAssignment.id), true);

    // Assignment lists and progress must stay within each user's class boundary.
    const jansenAssignments = await (await request('/api/assignments', { cookie: teacherJansen })).json() as Array<{ id: number }>;
    assert.equal(jansenAssignments.some((item) => item.id === sharedAssignment.id), true);
    const visserProgressResponse = await request(`/api/assignments/${sharedAssignment.id}/progress`, { cookie: teacherVisser });
    assert.equal(visserProgressResponse.status, 200);
    const visserProgress = await visserProgressResponse.json() as Array<{ student_email: string }>;
    assert.equal(visserProgress.some((item) => item.student_email === 'student.noor@demo.local'), false);
    assert.equal(visserProgress.some((item) => item.student_email === 'student.sara@demo.local'), true);
    assert.equal((await request(`/api/assignments/${sharedAssignment.id}/progress`, { cookie: studentSara })).status, 403);

    const noorAssignments = await (await request('/api/assignments', { cookie: studentNoor })).json() as Array<{ title: string }>;
    assert.ok(noorAssignments.some((item) => item.title === 'Netwerkontwerp'));
    assert.equal(noorAssignments.some((item) => item.title === 'Portfolio media'), false);
    assert.equal((await request('/api/assignments', { cookie: studentNoor, method: 'POST', body: { title: 'Student assignment', classIds: [ictClass.id] } })).status, 403);

    // Class creation and enrolment must be restricted to the assigned teacher/admin.
    const createClass = await request('/api/classes', {
      method: 'POST',
      cookie: teacherJansen,
      body: { name: 'HTTP Testklas', yearGroup: '2026–2027' },
    });
    assert.equal(createClass.status, 200);
    const testClass = await createClass.json() as { id: number };
    const adminClassResponse = await request('/api/classes', {
      method: 'POST', cookie: admin,
      body: { name: 'Admin Testklas', yearGroup: '2026–2027', teacherId: 2 },
    });
    assert.equal(adminClassResponse.status, 200, 'admin can create a class and assign an active teacher');
    const adminClass = await adminClassResponse.json() as { id: number };
    assert.equal((await request(`/api/classes/${adminClass.id}/students`, { cookie: teacherJansen })).status, 200);
    assert.equal((await request(`/api/classes/${adminClass.id}/students`, {
      method: 'POST', cookie: admin,
      body: { email: 'admin.enrolled@demo.local', displayName: 'Admin Enrolled Student', password: 'StudentEnrolment123!' },
    })).status, 200, 'admin can enroll a student in a class');
    assert.equal((await request(`/api/classes/${testClass.id}/students`, { cookie: teacherVisser })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, { cookie: admin })).status, 200,
      'admin can inspect any existing class');
    assert.equal((await request(`/api/classes/${testClass.id}/students`, {
      method: 'POST', cookie: admin,
      body: { email: 'admin.enrolled@demo.local', displayName: 'Admin Enrolled Student' },
    })).status, 200, 'admin can enroll an existing student in any class');
    assert.equal((await request(`/api/classes/${testClass.id}/students`, { cookie: studentNoor })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, {
      method: 'POST',
      cookie: teacherVisser,
      body: { email: 'new.student@demo.local', displayName: 'Nieuwe student', password: 'NewStudentPass123!' },
    })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, {
      method: 'POST',
      cookie: teacherJansen,
      body: { email: 'new.student@demo.local', displayName: 'Nieuwe student', password: 'NewStudentPass123!' },
    })).status, 200);
    const enrolled = await (await request(`/api/classes/${testClass.id}/students`, { cookie: teacherJansen })).json() as Array<{ email: string }>;
    assert.equal(enrolled.some((item) => item.email === 'new.student@demo.local'), true);
    assert.equal((await request('/api/classes', { cookie: studentNoor, method: 'POST', body: { name: 'Student class' } })).status, 403);

    // Empty and malformed JSON must produce controlled JSON errors, never an HTML/stack response.
    const emptyClassBody = await fetchWithCsrf(`${baseUrl}/api/classes`, {
      method: 'POST', headers: { Cookie: admin, 'Content-Type': 'application/json' }, body: '',
    });
    assert.equal(emptyClassBody.status, 400);
    assert.ok((emptyClassBody.headers.get('content-type') || '').includes('application/json'));
    const malformedJson = await fetchWithCsrf(`${baseUrl}/api/classes`, {
      method: 'POST', headers: { Cookie: admin, 'Content-Type': 'application/json' }, body: '{invalid',
    });
    assert.equal(malformedJson.status, 400);
    assert.ok((malformedJson.headers.get('content-type') || '').includes('application/json'));
    const emptyLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '',
    });
    assert.equal(emptyLogin.status, 401, 'empty login body must be treated as missing credentials');
    const primitiveJson = await fetchWithCsrf(`${baseUrl}/api/classes`, {
      method: 'POST', headers: { Cookie: admin, 'Content-Type': 'application/json' }, body: 'null',
    });
    assert.equal(primitiveJson.status, 400);

    // Invalid and missing resource identifiers must be handled deliberately, not leak SQLite errors.
    assert.equal((await request('/api/classes/not-a-number/students', { cookie: admin })).status, 400);
    assert.equal((await request('/api/classes/999999/students', { cookie: admin })).status, 404);
    assert.equal((await request('/api/classes/999999/students', {
      method: 'POST', cookie: admin,
      body: { email: 'ghost.student@demo.local', displayName: 'Ghost Student' },
    })).status, 404);
    assert.equal((await request('/api/assignments/not-a-number/progress', { cookie: admin })).status, 400);
    assert.equal((await request('/api/assignments/999999/progress', { cookie: admin })).status, 404);

    // Invalid and duplicate class references must return 400 instead of a database constraint error.
    assert.equal((await request('/api/assignments', {
      method: 'POST', cookie: admin,
      body: { title: 'Duplicate class IDs', classIds: [ictClass.id, ictClass.id] },
    })).status, 400);
    assert.equal((await request('/api/assignments', {
      method: 'POST', cookie: admin,
      body: { title: 'Missing class ID', classIds: [999999] },
    })).status, 400);
    assert.equal((await request('/api/assignments', {
      method: 'POST', cookie: admin,
      body: { title: 'Malformed class ID', classIds: ['not-a-number'] },
    })).status, 400);

    // Every numeric resource route should reject malformed IDs consistently.
    assert.equal((await request('/api/assignments/not-a-number', { method: 'DELETE', cookie: admin })).status, 400);
    assert.equal((await request('/api/assignments/not-a-number/submit', { method: 'POST', cookie: studentSara, body: new FormData() })).status, 400);
    assert.equal((await request('/api/submissions/not-a-number/feedback', {
      method: 'POST', cookie: teacherVisser, body: { comments: 'Test' },
    })).status, 400);
    assert.equal((await request('/api/submissions/not-a-number/download', { cookie: admin })).status, 400);
    assert.equal((await request('/api/submissions/999999/download', { cookie: admin })).status, 404);

    // Feedback validation and student write access.
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: teacherVisser,
      body: { comments: '   ' },
    })).status, 400);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: studentSara,
      body: { comments: 'Student attempts to grade' },
    })).status, 403);

    // Dashboard data must be role- and class-scoped.
    const jansenDashboardResponse = await request('/api/dashboard', { cookie: teacherJansen });
    assert.equal(jansenDashboardResponse.status, 200, 'teacher dashboard: ' + (await jansenDashboardResponse.clone().text()).slice(0, 1000));
    const jansenDashboard = await jansenDashboardResponse.json() as {
      classes: Array<{ name: string }>;
      assignments: Array<{ title: string }>;
    };
    assert.ok(jansenDashboard.classes.every((item) => ['ICT 2A', 'HTTP Testklas', 'Admin Testklas'].includes(item.name)));
    assert.equal(jansenDashboard.assignments.some((item) => item.title === 'Portfolio media'), false);
    const noorDashboardResponse = await request('/api/dashboard', { cookie: studentNoor });
    assert.equal(noorDashboardResponse.status, 200, 'student dashboard: ' + (await noorDashboardResponse.clone().text()).slice(0, 1000));
    const noorDashboard = await noorDashboardResponse.json() as {
      classes: Array<{ name: string }>;
      assignments: Array<{ title: string }>;
    };
    assert.deepEqual(noorDashboard.classes.map((item) => item.name), ['ICT 2A']);
    assert.equal(noorDashboard.assignments.some((item) => item.title === 'Portfolio media'), false);

    // Admin retains global access and admin-only user/audit operations.
    assert.equal((await request('/api/dashboard', { cookie: admin })).status, 200, 'admin dashboard must be available');
    assert.equal((await request('/api/admin/overview', { cookie: admin })).status, 200);
    assert.equal((await request('/api/admin/overview', { cookie: teacherJansen })).status, 403);
    assert.equal((await request('/api/admin/overview', { cookie: studentNoor })).status, 403);
    assert.equal((await request('/api/admin/audit', { cookie: admin })).status, 200);
    const adminUsers = await (await request('/api/admin/users', { cookie: admin })).json() as Array<{id:number;email:string;role:string}>;
    const seededStudent = adminUsers.find((item) => item.email === 'student.noor@demo.local');
    assert.ok(seededStudent);
    assert.equal((await request('/api/classes', {
      method: 'POST',
      cookie: admin,
      body: { name: 'Invalid teacher assignment', teacherId: seededStudent.id },
    })).status, 400, 'admin must not assign a student account as a class teacher');
    assert.equal((await request('/api/admin/audit', { cookie: teacherJansen })).status, 403);
    assert.equal((await request('/api/admin/audit', { cookie: studentNoor })).status, 403);
    assert.equal((await request('/api/admin/users', { cookie: studentNoor })).status, 403);
    const shortPasswordCreate = await request('/api/admin/users', {
      method: 'POST', cookie: admin,
      body: { email: 'http.short@demo.local', displayName: 'Too Short', role: 'teacher', password: 'Short123!xx' },
    });
    assert.equal(shortPasswordCreate.status, 400, 'new accounts must reject passwords shorter than 12 characters');
    const adminCreateUser = await request('/api/admin/users', {
      method: 'POST',
      cookie: admin,
      body: { email: 'http.created@demo.local', displayName: 'HTTP Created', role: 'teacher', password: 'SecurePass123!' },
    });
    assert.equal(adminCreateUser.status, 200);
    const createdUserId = (await adminCreateUser.json() as {id:number}).id;
    assert.equal((await request(`/api/admin/users/${createdUserId}`, {
      method: 'PATCH', cookie: admin, body: { password: 'Short123!xx' },
    })).status, 400, 'password changes must enforce the same minimum length');
    assert.equal((await request('/api/admin/users', { cookie: admin })).status, 200);
    assert.equal((await request('/api/admin/users', {
      method: 'POST',
      cookie: teacherJansen,
      body: { email: 'forbidden@demo.local', displayName: 'Forbidden', role: 'admin', password: 'SecurePass123!' },
    })).status, 403);
    assert.equal((await request('/api/admin/users', {
      method: 'POST',
      cookie: studentNoor,
      body: { email: 'student-forbidden@demo.local', displayName: 'Forbidden', role: 'student', password: 'SecurePass123!' },
    })).status, 403);

    // Unknown accounts and wrong passwords return the same public response.
    const knownWrongPassword = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:'admin@demo.local',password:'wrong-password'}),
    });
    const unknownAccount = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:'does-not-exist@demo.local',password:'wrong-password'}),
    });
    assert.equal(knownWrongPassword.status,401);
    assert.equal(unknownAccount.status,401);
    assert.equal(await unknownAccount.text(), await knownWrongPassword.text(),
      'unknown and existing accounts must have the same credential error response');

    const oversizedPassword = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:'admin@demo.local',password:'x'.repeat(1025)}),
    });
    assert.equal(oversizedPassword.status,401,'oversized password input must fail safely');

    // A successful login clears the identity bucket, allowing a fresh failure window.
    const resetIp = '198.51.100.22';
    for (let attempt=0; attempt<9; attempt+=1) {
      const response = await fetchWithCsrf(`${baseUrl}/api/login`, {
        method:'POST', headers:{'Content-Type':'application/json','X-Real-IP':resetIp},
        body:JSON.stringify({email:'admin@demo.local',password:'wrong-password'}),
      });
      assert.equal(response.status,401);
    }
    const resetSuccess = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST', headers:{'Content-Type':'application/json','X-Real-IP':resetIp},
      body:JSON.stringify({email:'admin@demo.local',password:'Admin123!'}),
    });
    assert.equal(resetSuccess.status,200,'a successful login must clear the identity failure bucket');
    for (let attempt=0; attempt<10; attempt+=1) {
      const response = await fetchWithCsrf(`${baseUrl}/api/login`, {
        method:'POST', headers:{'Content-Type':'application/json','X-Real-IP':resetIp},
        body:JSON.stringify({email:'admin@demo.local',password:'wrong-password'}),
      });
      assert.equal(response.status,401,'the identity bucket must start a new count after successful login');
    }
    const resetBucketBlocked = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST', headers:{'Content-Type':'application/json','X-Real-IP':resetIp},
      body:JSON.stringify({email:'admin@demo.local',password:'Admin123!'}),
    });
    assert.equal(resetBucketBlocked.status,429,'the reset identity bucket must block only after its new tenth failure');

    // Login throttling is scoped by client IP and normalized email, not by account alone.
    const limitedIp = '198.51.100.20';
    for (let attempt=0; attempt<10; attempt+=1) {
      const failedLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
        method:'POST',
        headers:{'Content-Type':'application/json','X-Real-IP':limitedIp,'X-Forwarded-For':`203.0.113.${attempt+1}`},
        body:JSON.stringify({email:'admin@demo.local',password:'wrong-password'}),
      });
      assert.equal(failedLogin.status,401,`failed attempt ${attempt+1} should retain the generic credential response`);
    }
    const blockedLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Real-IP':limitedIp},
      body:JSON.stringify({email:'ADMIN@DEMO.LOCAL',password:'Admin123!'}),
    });
    assert.equal(blockedLogin.status,429,'the next attempt must be rate limited');
    assert.ok(Number(blockedLogin.headers.get('retry-after'))>0,'429 must include a Retry-After value');
    assert.match(await blockedLogin.text(),/Te veel mislukte inlogpogingen/);

    const differentIpLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Real-IP':'198.51.100.21'},
      body:JSON.stringify({email:'admin@demo.local',password:'Admin123!'}),
    });
    assert.equal(differentIpLogin.status,200,
      'a failed-login bucket for one IP must not lock the account for every other IP');

    // The independent IP ceiling prevents an attacker rotating email addresses from bypassing throttling.
    const ipOnly='198.51.100.30';
    for (let attempt=0; attempt<30; attempt+=1) {
      const failedLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
        method:'POST',
        headers:{'Content-Type':'application/json','X-Real-IP':ipOnly},
        body:JSON.stringify({email:`unknown-${attempt}@demo.local`,password:'wrong-password'}),
      });
      assert.equal(failedLogin.status,401,`IP attempt ${attempt+1} should be accepted before the ceiling`);
    }
    const ipBlockedLogin = await fetchWithCsrf(`${baseUrl}/api/login`, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Real-IP':ipOnly},
      body:JSON.stringify({email:'another-unknown@demo.local',password:'wrong-password'}),
    });
    assert.equal(ipBlockedLogin.status,429,'the IP-wide ceiling must apply across different email addresses');
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([once(child, 'exit'), wait(3_000)]);
    }
    await rm(tempDir, { recursive: true, force: true });
  }
});
