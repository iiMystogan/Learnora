import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

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
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (chunk) => output.push(String(chunk)));
  child.stderr?.on('data', (chunk) => output.push(String(chunk)));
  const getOutput = () => output.join('');

  const request = async (
    route: string,
    options: { method?: string; cookie?: string; body?: unknown } = {},
  ) => {
    const headers: Record<string, string> = {};
    let body: BodyInit | undefined;
    if (options.cookie) headers.Cookie = options.cookie;
    if (options.body instanceof FormData) {
      body = options.body;
    } else if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.body);
    }
    return fetch(`${baseUrl}${route}`, {
      method: options.method || 'GET',
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

    // Unauthenticated requests must not expose protected resources.
    assert.equal((await request('/api/classes')).status, 401);

    const admin = await login('admin@demo.local', 'Admin123!');
    const teacherJansen = await login('docent.jansen@demo.local', 'Teacher123!');
    const teacherVisser = await login('docent.visser@demo.local', 'Teacher123!');
    const studentNoor = await login('student.noor@demo.local', 'Student123!');
    const studentSara = await login('student.sara@demo.local', 'Student123!');

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
    const jansenSubmissions = await (await request('/api/submissions', { cookie: teacherJansen })).json() as Array<{ id: number }>;
    assert.equal(jansenSubmissions.some((item) => item.id === submission.id), false);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: teacherJansen,
      body: { comments: 'Unauthorized feedback', grade: '1' },
    })).status, 404);
    assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: teacherJansen })).status, 403);
    assert.equal((await request(`/api/submissions/${submission.id}/download`, { cookie: studentNoor })).status, 403);

    // Visser teaches Media 3B and should be allowed to access Sara's submission.
    const visserSubmissions = await (await request('/api/submissions', { cookie: teacherVisser })).json() as Array<{ id: number }>;
    assert.equal(visserSubmissions.some((item) => item.id === submission.id), true);
    assert.equal((await request(`/api/submissions/${submission.id}/feedback`, {
      method: 'POST',
      cookie: teacherVisser,
      body: { comments: 'Authorized feedback', grade: '8' },
    })).status, 200);
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
    assert.equal((await request(`/api/classes/${testClass.id}/students`, { cookie: teacherVisser })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, { cookie: studentNoor })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, {
      method: 'POST',
      cookie: teacherVisser,
      body: { email: 'new.student@demo.local', displayName: 'Nieuwe student' },
    })).status, 403);
    assert.equal((await request(`/api/classes/${testClass.id}/students`, {
      method: 'POST',
      cookie: teacherJansen,
      body: { email: 'new.student@demo.local', displayName: 'Nieuwe student' },
    })).status, 200);
    const enrolled = await (await request(`/api/classes/${testClass.id}/students`, { cookie: teacherJansen })).json() as Array<{ email: string }>;
    assert.equal(enrolled.some((item) => item.email === 'new.student@demo.local'), true);
    assert.equal((await request('/api/classes', { cookie: studentNoor, method: 'POST', body: { name: 'Student class' } })).status, 403);

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
    assert.ok(jansenDashboard.classes.every((item) => item.name === 'ICT 2A' || item.name === 'HTTP Testklas'));
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
    assert.equal((await request('/api/admin/overview', { cookie: admin })).status, 200);
    assert.equal((await request('/api/admin/audit', { cookie: admin })).status, 200);
    assert.equal((await request('/api/admin/audit', { cookie: teacherJansen })).status, 403);
    assert.equal((await request('/api/admin/users', { cookie: studentNoor })).status, 403);
    const adminCreateUser = await request('/api/admin/users', {
      method: 'POST',
      cookie: admin,
      body: { email: 'http.created@demo.local', displayName: 'HTTP Created', role: 'teacher', password: 'SecurePass123!' },
    });
    assert.equal(adminCreateUser.status, 200);
    assert.equal((await request('/api/admin/users', { cookie: admin })).status, 200);
    assert.equal((await request('/api/admin/users', {
      method: 'POST',
      cookie: teacherJansen,
      body: { email: 'forbidden@demo.local', displayName: 'Forbidden', role: 'admin', password: 'SecurePass123!' },
    })).status, 403);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([once(child, 'exit'), wait(3_000)]);
    }
    await rm(tempDir, { recursive: true, force: true });
  }
});
