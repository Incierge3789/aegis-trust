// aegis.yaml policy configuration loader.
//
// TS port of aegis.config (Python). Mirrors:
//   - load_config(path?) -> dict
//   - get_purpose_policy(purpose) -> { scope } | { deny_fields } | null
//   - reset_config()
//
// YAML parsing is via optional dep `yaml` (npm install yaml). If absent,
// load_config throws a Python-style ImportError with install hint. Mirrors
// the `pip install aegis-trust[yaml]` UX.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { aegisDocsUrl, AegisConfigError } from "./errors.js";

let _config: Record<string, unknown> | null = null;
let _configPath: string | null = null;

export interface PurposeConfigScope {
  readonly scope: ReadonlyArray<string>;
}
export interface PurposeConfigDeny {
  readonly denyFields: ReadonlyArray<string>;
}
export type PurposeConfig = PurposeConfigScope | PurposeConfigDeny;

const FIELD_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;

// Mirror Python `_validate_field_path` from shield.py — single identifier per
// segment, dot-separated. Wildcards / array index are not supported.
function validateFieldPath(p: string): void {
  if (!FIELD_PATH_RE.test(p)) {
    throw new AegisConfigError({
      code: "aegis.config.fieldPath.invalid",
      remediation: "Use dot-separated identifiers (e.g. 'profile.address.city'). Wildcards / array index unsupported.",
      docs_url: aegisDocsUrl("aegis.config.fieldPath.invalid"),
      message:
        `Invalid field path '${p}': must be dot-separated identifiers `
          + `(e.g. 'profile.address.city')`,
    });
  }
}

function findConfigFile(): string | null {
  const envPath = process.env.AEGIS_CONFIG;
  if (envPath) {
    return existsSync(envPath) ? envPath : null;
  }
  for (const name of ["aegis.yaml", "aegis.yml"]) {
    if (existsSync(name)) return resolve(name);
  }
  return null;
}

function validateConfig(config: Record<string, unknown>): void {
  const purposes = config.purposes;
  if (purposes === undefined || purposes === null) return; // empty is valid

  if (
    typeof purposes !== "object"
    || Array.isArray(purposes)
  ) {
    throw new AegisConfigError({
      code: "aegis.config.purposes.notMapping",
      remediation: "Set top-level 'purposes' to a mapping. Example: purposes:\\n  support:\\n    scope: ['name', 'issue']",
      docs_url: aegisDocsUrl("aegis.config.purposes.notMapping"),
      message:
        "'purposes' must be a mapping of purpose name to policy. "
          + "Example:\n  purposes:\n    support:\n      scope: ['name', 'issue']",
    });
  }

  for (const [name, policyRaw] of Object.entries(purposes)) {
    if (
      !policyRaw
      || typeof policyRaw !== "object"
      || Array.isArray(policyRaw)
    ) {
      throw new AegisConfigError({
        code: "aegis.config.purpose.notMapping",
        remediation: "Each purpose entry must be a mapping with `scope` or `deny_fields`.",
        docs_url: aegisDocsUrl("aegis.config.purpose.notMapping"),
        message: `Purpose '${name}' must be a mapping containing scope or deny_fields.`,
      });
    }
    const policy = policyRaw as Record<string, unknown>;
    const hasScope = "scope" in policy;
    const hasDeny = "deny_fields" in policy || "denyFields" in policy;

    if (hasScope && hasDeny) {
      throw new AegisConfigError({
        code: "aegis.config.purpose.scopeDenyConflict",
        remediation: "Use either `scope` (allow-list) or `deny_fields` (block-list) per purpose, never both.",
        docs_url: aegisDocsUrl("aegis.config.purpose.scopeDenyConflict"),
        message:
          `Purpose '${name}': scope and deny_fields are mutually exclusive. `
            + `Use scope (whitelist) OR deny_fields (blacklist), not both.`,
      });
    }
    if (!hasScope && !hasDeny) {
      throw new AegisConfigError({
        code: "aegis.config.purpose.empty",
        remediation: "Add `scope: [...]` or `deny_fields: [...]` to the purpose entry.",
        docs_url: aegisDocsUrl("aegis.config.purpose.empty"),
        message: `Purpose '${name}': either scope or deny_fields is required.`,
      });
    }

    for (const key of ["scope", "deny_fields", "denyFields"]) {
      const fields = policy[key];
      if (fields === undefined) continue;
      if (!Array.isArray(fields)) {
        throw new AegisConfigError({
          code: "aegis.config.fields.notList",
          remediation: `Set \`${key}\` to a YAML list of field name strings.`,
          docs_url: aegisDocsUrl("aegis.config.fields.notList"),
          message: `Purpose '${name}': ${key} must be a list of field names.`,
        });
      }
      for (const field of fields) {
        if (typeof field !== "string") {
          throw new AegisConfigError({
            code: "aegis.config.fields.elementNotString",
            remediation: `Each entry in \`${key}\` must be a string field path.`,
            docs_url: aegisDocsUrl("aegis.config.fields.elementNotString"),
            message: `Purpose '${name}': ${key} elements must be strings.`,
          });
        }
        validateFieldPath(field);
      }
    }

    const denyList = policy.deny_fields ?? policy.denyFields;
    if (hasDeny && Array.isArray(denyList) && denyList.length === 0) {
      throw new AegisConfigError({
        code: "aegis.config.denyFields.empty",
        remediation: "Provide at least one field path in `deny_fields`, or remove the key entirely.",
        docs_url: aegisDocsUrl("aegis.config.denyFields.empty"),
        message:
          `Purpose '${name}': deny_fields must not be empty. `
            + `An empty deny list hides nothing.`,
      });
    }
  }
}

export async function loadConfig(
  path?: string,
): Promise<Record<string, unknown>> {
  if (_config !== null && (path === undefined || path === _configPath)) {
    return _config;
  }

  // Optional YAML dep — match Python's `pip install aegis-trust[yaml]` UX.
  let parseYaml: ((src: string) => unknown) | null = null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const yamlMod: any = await import(/* @vite-ignore */ "yaml" as string);
    parseYaml = (src: string) => yamlMod.parse(src);
  } catch {
    throw new AegisConfigError({
      code: "aegis.config.yamlMissing",
      remediation: "Install the optional `yaml` dependency: `npm install yaml`.",
      docs_url: aegisDocsUrl("aegis.config.yamlMissing"),
      message:
        "Module 'yaml' is required to use aegis.yaml config. "
          + "Install it with: npm install yaml",
    });
  }

  const resolved = path ?? findConfigFile();
  if (resolved === null) {
    throw new AegisConfigError({
      code: "aegis.config.fileNotFound",
      remediation: "Create `aegis.yaml` in CWD or set the `AEGIS_CONFIG` env var to a YAML file path.",
      docs_url: aegisDocsUrl("aegis.config.fileNotFound"),
      message: "No aegis config file found. Create aegis.yaml or set AEGIS_CONFIG env var.",
    });
  }

  const src = readFileSync(resolved, "utf8");
  let raw: unknown;
  try {
    raw = parseYaml(src);
  } catch (cause) {
    // codex round 1 P2: YAML parse failures escaped as raw parser errors,
    // breaking the machine-parseable error contract for FULL-mode agents.
    throw new AegisConfigError({
      code: "aegis.config.yamlParseError",
      remediation: "Fix the YAML syntax in `aegis.yaml`. Run `yq . aegis.yaml` to locate the parse error.",
      docs_url: aegisDocsUrl("aegis.config.yamlParseError"),
      message: `aegis config YAML parse error in ${resolved}`,
      cause,
    });
  }

  if (
    raw === null
    || raw === undefined
    || typeof raw !== "object"
    || Array.isArray(raw)
  ) {
    throw new AegisConfigError({
      code: "aegis.config.topLevel.notMapping",
      remediation: "Top-level config must be a YAML mapping with a 'purposes' key.",
      docs_url: aegisDocsUrl("aegis.config.topLevel.notMapping"),
      message:
        `aegis config must be a YAML mapping, got ${typeof raw}. `
          + "The top-level structure should be a mapping with a 'purposes' key.",
    });
  }

  validateConfig(raw as Record<string, unknown>);
  _config = raw as Record<string, unknown>;
  _configPath = resolved;
  return _config;
}

export async function getPurposePolicy(
  purpose: string,
): Promise<PurposeConfig | null> {
  let config: Record<string, unknown>;
  try {
    config = await loadConfig();
  } catch {
    return null;
  }
  const purposes = config.purposes as
    | Record<string, Record<string, unknown>>
    | undefined;
  if (!purposes) return null;
  const policy = purposes[purpose];
  if (!policy) return null;
  if (Array.isArray(policy.scope)) {
    return { scope: policy.scope as ReadonlyArray<string> };
  }
  const deny = policy.deny_fields ?? policy.denyFields;
  if (Array.isArray(deny)) {
    return { denyFields: deny as ReadonlyArray<string> };
  }
  return null;
}

export function resetConfig(): void {
  _config = null;
  _configPath = null;
}
