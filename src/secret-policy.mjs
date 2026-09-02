import { execFileSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";

const MAX_SCANNED_BYTES = 1024 * 1024;
const LEGACY_SOPS_SUFFIX = /\.sops\.(?:env|json|ya?ml|ini)$/u;
const ENV_CIPHERTEXT_SUFFIX = /\.env\.enc$/u;
const SOPS_CONFIG = /^\.sops\.ya?ml$/u;
const APPROVED_LEGACY_SOPS_PATH = /^secrets\/.+\.sops\.env$/u;
const APPROVED_ENV_CIPHERTEXT = /^env\/enc\/(?:dev|prod)\.env\.enc$/u;
const SECRET_DOCUMENT = /^secrets\/(?:README\.md|\.gitkeep)$/u;
const DOTENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const SOPS_ENCRYPTED_VALUE = /^ENC\[[^\r\n]+\]$/u;
const SOPS_AGE_FIELD = /^sops_age__list_(\d+)__map_(enc|recipient)$/u;
const SOPS_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

const sensitivePatterns = [
  ["age-private-key", new RegExp(["AGE", "SECRET", "KEY"].join("-") + "-")],
  [
    "pem-private-key",
    new RegExp("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
  ],
  ["github-classic-token", new RegExp("gh" + "p_[A-Za-z0-9]{30,}")],
  ["github-other-token", new RegExp("gh" + "[ousr]_[A-Za-z0-9]{30,}")],
  [
    "github-fine-grained-token",
    new RegExp("github_" + "pat_[A-Za-z0-9_]{40,}"),
  ],
  ["linear-api-token", new RegExp("lin_" + "api_[A-Za-z0-9]{20,}")],
  [
    "google-chat-bridge-token",
    new RegExp(
      ["CHAT", "BRIDGE", "TOKEN"].join("_") +
        String.raw`[ \t]*=[ \t]*["']?[A-Za-z0-9_-]{30,}`,
    ),
  ],
  ["aws-access-key", new RegExp("AK" + "IA[0-9A-Z]{16}")],
];

function normalizePath(path) {
  return path.split(sep).join("/").replace(/^\.\//u, "");
}

function finding(path, rule, detail) {
  return { path, rule, detail };
}

function isSopsArtifactPath(path) {
  return LEGACY_SOPS_SUFFIX.test(path) || ENV_CIPHERTEXT_SUFFIX.test(path);
}

function isApprovedSopsPath(path) {
  return (
    APPROVED_LEGACY_SOPS_PATH.test(path) ||
    APPROVED_ENV_CIPHERTEXT.test(path)
  );
}

function isDotenvExample(name) {
  return (
    [".env.example", ".env.sample", ".env.template"].includes(name) ||
    /\.(?:example|sample|template)\.env$/u.test(name) ||
    /\.env\.(?:example|sample|template)$/u.test(name)
  );
}

export function isPlaintextDotenvPath(path) {
  const normalized = normalizePath(path);
  const name = basename(normalized);
  if (isDotenvExample(name)) return false;
  if (SOPS_CONFIG.test(normalized) || isSopsArtifactPath(normalized)) return false;
  return (
    normalized.startsWith("env/dec/") ||
    name === ".env" ||
    name.startsWith(".env.") ||
    name.endsWith(".env")
  );
}

function validAgeEnvelope(value) {
  return (
    value.startsWith("-----BEGIN AGE ENCRYPTED FILE-----\\n") &&
    value.includes("\\n-----END AGE ENCRYPTED FILE-----")
  );
}

export function validateSopsDotenv(content) {
  if (typeof content !== "string" || content.includes("\0")) return false;

  const entries = new Map();
  for (const line of content.split(/\r?\n/u)) {
    if (line.trim() === "" || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) return false;
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!DOTENV_KEY.test(key) || entries.has(key)) return false;
    entries.set(key, value);
  }

  let encryptedValues = 0;
  const age = new Map();
  for (const [key, value] of entries) {
    const ageField = key.match(SOPS_AGE_FIELD);
    if (ageField) {
      const [, index, field] = ageField;
      const pair = age.get(index) ?? {};
      pair[field] = value;
      age.set(index, pair);
      continue;
    }

    if (!key.startsWith("sops_")) {
      encryptedValues += 1;
      if (!SOPS_ENCRYPTED_VALUE.test(value)) return false;
      continue;
    }

    switch (key) {
      case "sops_mac":
        if (!SOPS_ENCRYPTED_VALUE.test(value)) return false;
        break;
      case "sops_version":
        if (!SOPS_VERSION.test(value)) return false;
        break;
      case "sops_lastmodified":
        if (!Number.isFinite(Date.parse(value)) || !value.endsWith("Z")) {
          return false;
        }
        break;
      case "sops_unencrypted_suffix":
        if (value !== "_unencrypted") return false;
        break;
      case "sops_encrypted_suffix":
        if (value !== "_encrypted") return false;
        break;
      case "sops_mac_only_encrypted":
        if (value !== "true" && value !== "false") return false;
        break;
      default:
        return false;
    }
  }

  if (
    encryptedValues === 0 ||
    !entries.has("sops_mac") ||
    !entries.has("sops_version") ||
    age.size === 0
  ) {
    return false;
  }

  for (const pair of age.values()) {
    if (
      !/^age1[0-9a-z]{20,}$/u.test(pair.recipient ?? "") ||
      !validAgeEnvelope(pair.enc ?? "")
    ) {
      return false;
    }
  }
  return true;
}

// Retained for consumers of the initial API; it now performs the full strict
// validation rather than checking for marker substrings only.
export function hasSopsDotenvMetadata(content) {
  return validateSopsDotenv(content);
}

export function sensitiveTextRules(content) {
  return sensitivePatterns
    .filter(([, pattern]) => pattern.test(content))
    .map(([rule]) => rule);
}

function trackedFiles(root) {
  const output = execFileSync("git", ["-C", root, "ls-files", "-z"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return output.split("\0").filter(Boolean).map(normalizePath).sort();
}

export async function scanTrackedRepository(rootInput) {
  const root = resolve(rootInput);
  const findings = [];

  for (const trackedPath of trackedFiles(root)) {
    if (CONTROL_CHARACTER.test(trackedPath) || trackedPath.includes("\ufffd")) {
      findings.push(
        finding(
          trackedPath,
          "unsafe-tracked-path",
          "tracked paths must not contain control or undecodable characters",
        ),
      );
      continue;
    }

    if (isPlaintextDotenvPath(trackedPath)) {
      findings.push(
        finding(
          trackedPath,
          "tracked-plaintext-env",
          "plaintext dotenv files must not be tracked",
        ),
      );
    }

    if (
      isSopsArtifactPath(trackedPath) &&
      !SOPS_CONFIG.test(trackedPath) &&
      !isApprovedSopsPath(trackedPath) &&
      !trackedPath.startsWith("secrets/") &&
      !trackedPath.startsWith("env/enc/")
    ) {
      findings.push(
        finding(
          trackedPath,
          "sops-outside-approved-path",
          "SOPS artifacts must use secrets/*.sops.env or env/enc/dev|prod.env.enc",
        ),
      );
    }

    if (trackedPath.startsWith("env/enc/") && !APPROVED_ENV_CIPHERTEXT.test(trackedPath)) {
      findings.push(
        finding(
          trackedPath,
          isSopsArtifactPath(trackedPath)
            ? "noncanonical-encrypted-env"
            : "unencrypted-secret-path",
          "env/enc accepts only validated dev.env.enc and prod.env.enc ciphertext",
        ),
      );
    }

    if (trackedPath.startsWith("secrets/") && !SECRET_DOCUMENT.test(trackedPath)) {
      if (
        isSopsArtifactPath(trackedPath) &&
        !APPROVED_LEGACY_SOPS_PATH.test(trackedPath)
      ) {
        findings.push(
          finding(
            trackedPath,
            "unsupported-sops-format",
            "legacy secrets paths validate only .sops.env artifacts",
          ),
        );
      } else if (!APPROVED_LEGACY_SOPS_PATH.test(trackedPath)) {
        findings.push(
          finding(
            trackedPath,
            "unencrypted-secret-path",
            "files under secrets/ must use a validated .sops.env path",
          ),
        );
      }
    }

    const absolutePath = resolve(root, trackedPath);
    const rel = relative(root, absolutePath);
    if (isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) {
      findings.push(
        finding(
          trackedPath,
          "path-escape",
          "tracked path resolves outside the repository",
        ),
      );
      continue;
    }

    const stat = await lstat(absolutePath);
    if (stat.isSymbolicLink()) {
      findings.push(
        finding(
          trackedPath,
          "tracked-symlink",
          "secret scanning refuses tracked symlinks",
        ),
      );
      continue;
    }
    if (!stat.isFile()) continue;
    if (stat.size > MAX_SCANNED_BYTES) {
      findings.push(
        finding(
          trackedPath,
          "oversized-tracked-file",
          `tracked files larger than ${MAX_SCANNED_BYTES} bytes require explicit review or removal`,
        ),
      );
      continue;
    }

    const bytes = await readFile(absolutePath);
    const content = bytes.toString("utf8");

    if (isApprovedSopsPath(trackedPath) && !validateSopsDotenv(content)) {
      findings.push(
        finding(
          trackedPath,
          "invalid-sops-dotenv",
          "encrypted dotenv must contain only encrypted data and valid age/SOPS metadata",
        ),
      );
    }

    // Strict SOPS validation already proves that user values are ciphertext.
    // Scan every other tracked text/binary file for credential signatures.
    if (!isApprovedSopsPath(trackedPath)) {
      for (const rule of sensitiveTextRules(bytes.toString("latin1"))) {
        findings.push(
          finding(
            trackedPath,
            rule,
            "sensitive material must not be tracked",
          ),
        );
      }
    }
  }

  return findings;
}
