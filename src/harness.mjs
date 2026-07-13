// Shared browser-test harness for fiducia.cloud.
//
// Design goals (see README): keep shared code MINIMAL and framework-agnostic.
// Playwright and Puppeteer are consumed by each repo as libraries under Node's
// built-in `node --test` runner; this module only provides:
//   - chromeExecutablePath(): locate a system Chrome/Chromium for either driver
//   - launchOptions:          shared headless/viewport defaults
//   - startServer():          boot a real app server on an ephemeral port, wait
//                             for a readiness path, and return { url, stop }.
//
// Specs stay 100% in each repo's own tests/ directory. A repo composes a thin
// local harness (e.g. startAdminServer / startCustomerPortal) on top of
// startServer() so the boot recipe lives next to the app it boots.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

/**
 * Locate a Chrome/Chromium binary usable by both Playwright and Puppeteer.
 * Honors CHROME_BIN / PUPPETEER_EXECUTABLE_PATH / PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
 * first, then falls back to common OS install paths. Throws if none is found so
 * CI fails loudly instead of hanging on a missing browser.
 */
export function chromeExecutablePath() {
  const candidates = [
    process.env.CHROME_BIN,
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);

  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(
      "No Chrome/Chromium executable found. Set CHROME_BIN to run browser tests.",
    );
  }

  return found;
}

/** Shared browser launch defaults. Spread into a driver-specific launch call. */
export const launchOptions = Object.freeze({
  headless: true,
  viewport: Object.freeze({ width: 1440, height: 900 }),
});

function pickPort([low, high]) {
  return low + Math.floor(Math.random() * (high - low));
}

/**
 * Boot an application server for E2E and wait until it answers `readyPath`.
 *
 * @param {object} opts
 * @param {string} opts.command                 executable to spawn (e.g. "cargo", "npm", process.execPath)
 * @param {string[]} [opts.args]                arguments
 * @param {string} [opts.cwd]                   working directory
 * @param {Record<string,string>} [opts.env]   extra env (merged over process.env)
 * @param {string} [opts.readyPath]            path polled for a 2xx before resolving (default "/")
 * @param {string} [opts.portEnv]              env var the server reads its port from (default "PORT")
 * @param {(port:number)=>string[]} [opts.portArgs]  build extra CLI args for the chosen port (e.g. p => ["--port", String(p)]); use for servers that take --port instead of $PORT
 * @param {[number,number]} [opts.portRange]   [inclusiveLow, exclusiveHigh) ephemeral port window
 * @param {string} [opts.reuseUrlEnv]          if set and present in env, reuse that URL instead of spawning
 * @param {number} [opts.startupTimeoutMs]     readiness deadline (default 60000)
 * @returns {Promise<{url: string, stop: () => Promise<void>}>}
 */
export async function startServer({
  command,
  args = [],
  cwd,
  env = {},
  readyPath = "/",
  portEnv = "PORT",
  portArgs,
  portRange = [19000, 20000],
  reuseUrlEnv,
  startupTimeoutMs = 60000,
}) {
  if (reuseUrlEnv && process.env[reuseUrlEnv]) {
    return {
      url: process.env[reuseUrlEnv].replace(/\/$/, ""),
      stop: async () => {},
    };
  }

  const port = pickPort(portRange);
  const url = `http://127.0.0.1:${port}`;
  const logs = [];
  // Some servers take their port via CLI (astro/vite preview: `--port N`) rather
  // than $PORT. portArgs(port) lets a caller inject those args for the chosen port.
  const spawnArgs = portArgs ? [...args, ...portArgs(port)] : args;
  const child = spawn(command, spawnArgs, {
    cwd,
    env: { ...process.env, ...env, [portEnv]: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
    // npm and similar launchers create a grandchild for the real server. Give
    // that tree its own POSIX process group so stop() cannot orphan the server
    // (and its inherited stdio) after only terminating the launcher.
    detached: process.platform !== "win32",
  });

  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));

  try {
    await waitForHttp(`${url}${readyPath}`, child, logs, startupTimeoutMs);
  } catch (error) {
    signalProcessTree(child, "SIGTERM");
    throw error;
  }

  return {
    url,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }

      signalProcessTree(child, "SIGTERM");
      await Promise.race([
        new Promise((resolveStop) => child.once("exit", resolveStop)),
        delay(2500).then(() => {
          if (child.exitCode === null && child.signalCode === null) {
            signalProcessTree(child, "SIGKILL");
          }
        }),
      ]);
    },
  };
}

function signalProcessTree(child, signal) {
  try {
    if (process.platform !== "win32" && child.pid) {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") {
      throw error;
    }
  }
}

async function waitForHttp(url, child, logs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`server exited before ${url} was ready:\n${logs.join("")}`);
    }

    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling until the listener is ready.
    }

    await delay(250);
  }

  throw new Error(`timed out waiting for ${url}:\n${logs.join("")}`);
}
