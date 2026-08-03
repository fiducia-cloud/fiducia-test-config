import { execFileSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";

const MAX_SCANNED_BYTES = 1024 * 1024;
const SOPS_SUFFIX = /\.sops\.(?:env|json|ya?ml|ini)$/u;
const SECRET_DOCUMENT = /^secrets\/(?:README\.md|\.gitkeep)$/u;

const sensitivePatterns = [
  ["age-private-key", new RegExp(["AGE", "SECRET", "KEY"].join("-") + "-")],
  ["pem-private-key", new RegExp("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")],
  ["github-classic-token", new RegExp("gh" + "p_[A-Za-z0-9]{30,}")],
  ["github-fine-grained-token", new RegExp("github_" + "pat_[A-Za-z0-9_]{40,}")],
  ["linear-api-token", new RegExp("lin_" + "api_[A-Za-z0-9]{20,}")],
  ["aws-access-key", new RegExp("AK" + "IA[0-9A-Z]{16}")],
];

function normalizePath(path) {
  return path.split(sep).join("/").replace(/^\.\//u, "");
}

function finding(path, rule, detail) {
  return { path, rule, detail };
}

export function isPlaintextDotenvPath(path) {
  const name = basename(path);
  if (name === ".env.example" || name === ".env.sample") return false;
  if (SOPS_SUFFIX.test(name)) return false;
  return name === ".env" || name.startsWith(".env.");
}

export function hasSopsDotenvMetadata(content) {
  return [
    "sops_age__list_0__map_enc=",
    "sops_age__list_0__map_recipient=",
    "sops_mac=ENC[",
    "sops_version=",
  ].every((marker) => content.includes(marker));
}

export function sensitiveTextRules(content) {
  return sensitivePatterns.filter(([, pattern]) => pattern.test(content)).map(([rule]) => rule);
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
    if (isPlaintextDotenvPath(trackedPath)) {
      findings.push(finding(trackedPath, "tracked-plaintext-env", "plaintext dotenv files must not be tracked"));
    }

    if (trackedPath.startsWith("secrets/") && !SECRET_DOCUMENT.test(trackedPath) && !SOPS_SUFFIX.test(trackedPath)) {
      findings.push(
        finding(trackedPath, "unencrypted-secret-path", "files under secrets/ must use an approved .sops.* suffix"),
      );
    }

    const absolutePath = resolve(root, trackedPath);
    const rel = relative(root, absolutePath);
    if (isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) {
      findings.push(finding(trackedPath, "path-escape", "tracked path resolves outside the repository"));
      continue;
    }

    const stat = await lstat(absolutePath);
    if (stat.isSymbolicLink()) {
      findings.push(finding(trackedPath, "tracked-symlink", "secret scanning refuses tracked symlinks"));
      continue;
    }
    if (!stat.isFile() || stat.size > MAX_SCANNED_BYTES) continue;

    const bytes = await readFile(absolutePath);
    if (bytes.includes(0)) continue;
    const content = bytes.toString("utf8");

    if (trackedPath.endsWith(".sops.env") && !hasSopsDotenvMetadata(content)) {
      findings.push(
        finding(trackedPath, "invalid-sops-dotenv", "encrypted dotenv file is missing required SOPS metadata"),
      );
    }

    for (const rule of sensitiveTextRules(content)) {
      findings.push(finding(trackedPath, rule, "sensitive material must not be tracked"));
    }
  }

  return findings;
}
