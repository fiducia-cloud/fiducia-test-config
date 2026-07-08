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
