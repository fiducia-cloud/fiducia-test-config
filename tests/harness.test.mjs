// Self-tests for the harness: exercise chromeExecutablePath and the startServer
// lifecycle against a trivial Node HTTP server (no real browser required).
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromeExecutablePath, launchOptions, startServer } from "../src/harness.mjs";

test("chromeExecutablePath honors CHROME_BIN when it points at a real file", () => {
  const previous = process.env.CHROME_BIN;
  process.env.CHROME_BIN = process.execPath; // the node binary certainly exists
  try {
    assert.equal(chromeExecutablePath(), process.execPath);
  } finally {
    if (previous === undefined) {
      delete process.env.CHROME_BIN;
    } else {
      process.env.CHROME_BIN = previous;
    }
  }
});

test("launchOptions exposes headless + viewport defaults", () => {
  assert.equal(launchOptions.headless, true);
  assert.equal(launchOptions.viewport.width, 1440);
  assert.equal(launchOptions.viewport.height, 900);
});

test("startServer boots a server, serves readyPath, then stops it", async (t) => {
  const script =
    "const http=require('http');" +
    "http.createServer((_q,s)=>{s.writeHead(200);s.end('ok')})" +
    ".listen(process.env.PORT,'127.0.0.1');";

  const server = await startServer({
    command: process.execPath,
    args: ["-e", script],
    cwd: process.cwd(),
    readyPath: "/",
    portRange: [21000, 21999],
    startupTimeoutMs: 15000,
  });
  t.after(() => server.stop());

  const response = await fetch(`${server.url}/`);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "ok");

  await server.stop();
  await assert.rejects(fetch(`${server.url}/`)); // listener is gone
});

test("startServer stops descendant servers in the spawned process group", async (t) => {
  const descendant =
    "const http=require('http');" +
    "http.createServer((_q,s)=>{s.writeHead(200);s.end('child')})" +
    ".listen(process.env.PORT,'127.0.0.1');";
  const wrapper =
    "const {spawn}=require('child_process');" +
    `spawn(process.execPath,['-e',${JSON.stringify(descendant)}],` +
    "{env:process.env,stdio:'ignore'});" +
    "setInterval(()=>{},10000);";

  const server = await startServer({
    command: process.execPath,
    args: ["-e", wrapper],
    cwd: process.cwd(),
    readyPath: "/",
    portRange: [24000, 24999],
    startupTimeoutMs: 15000,
  });
  t.after(() => server.stop());

  assert.equal(await (await fetch(server.url)).text(), "child");
  await server.stop();
  await assert.rejects(fetch(server.url));
});

test("startServer reuses a *_TEST_URL env instead of spawning", async () => {
  const previous = process.env.FIDUCIA_TEST_REUSE_URL;
  process.env.FIDUCIA_TEST_REUSE_URL = "http://reuse.example:1234/";
  try {
    const server = await startServer({
      command: "definitely-not-a-real-binary",
      reuseUrlEnv: "FIDUCIA_TEST_REUSE_URL",
    });
    assert.equal(server.url, "http://reuse.example:1234"); // trailing slash trimmed
    await server.stop(); // no-op, must not throw
  } finally {
    if (previous === undefined) {
      delete process.env.FIDUCIA_TEST_REUSE_URL;
    } else {
      process.env.FIDUCIA_TEST_REUSE_URL = previous;
    }
  }
});

test("startServer injects the chosen port via portArgs (--port style)", async (t) => {
  const script =
    "const http=require('http');const a=process.argv;const p=a[a.indexOf('--port')+1];" +
    "http.createServer((_q,s)=>{s.writeHead(200);s.end('argport')}).listen(p,'127.0.0.1');";

  const server = await startServer({
    command: process.execPath,
    // `--` so node stops parsing its own options and forwards --port to the script,
    // mirroring how a real `astro preview` / `vite preview` receives --port.
    args: ["-e", script, "--"],
    portArgs: (port) => ["--port", String(port)],
    cwd: process.cwd(),
    portRange: [23000, 23999],
    startupTimeoutMs: 15000,
  });
  t.after(() => server.stop());

  const response = await fetch(server.url);
  assert.equal(await response.text(), "argport");
});

test("stop() is retry-safe: repeated and concurrent calls settle without dangling processes", async () => {
  const script =
    "const http=require('http');" +
    "http.createServer((_q,s)=>{s.writeHead(200);s.end('ok')})" +
    ".listen(process.env.PORT,'127.0.0.1');";

  const server = await startServer({
    command: process.execPath,
    args: ["-e", script],
    cwd: process.cwd(),
    readyPath: "/",
    portRange: [26000, 26999],
    startupTimeoutMs: 15000,
  });
  assert.equal((await fetch(server.url)).status, 200);

  // Concurrent stops (a test body racing its own t.after cleanup) must both
  // settle without throwing…
  await Promise.all([server.stop(), server.stop()]);
  // …and repeated stops after completion are cheap no-ops.
  await server.stop();
  await server.stop();

  // Nothing is left listening on the port.
  await assert.rejects(fetch(server.url));
});

test("startServer rejects when the server never becomes ready", async () => {
  await assert.rejects(
    startServer({
      command: process.execPath,
      args: ["-e", "setTimeout(()=>{}, 10000)"], // never listens
      cwd: process.cwd(),
      readyPath: "/",
      portRange: [22000, 22999],
      startupTimeoutMs: 1200,
    }),
    /timed out waiting for/,
  );
});

test("startServer reports spawn failures without leaking an error event", async () => {
  await assert.rejects(
    startServer({
      command: "fiducia-command-that-does-not-exist",
      portRange: [25000, 25999],
      startupTimeoutMs: 15000,
    }),
    /server failed to spawn.*ENOENT/s,
  );
});
