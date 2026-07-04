// Aegis Trust error model — machine-parseable errors for agent retry.
//
// Every error carries `code` + `remediation` + `docs_url` so agents can
// route on the code, surface the remediation to a human or a coding model,
// and follow the docs_url for canonical guidance. Mirror of the Sentry
// archetype error envelope — no free-text guessing required for retry.

export interface AegisErrorPayload {
  readonly code: string;
  readonly remediation: string;
  readonly docs_url: string;
  readonly message: string;
  readonly cause?: unknown;
}

// Base class. All Aegis SDK errors extend this. Catch this at the agent
// boundary; switch on `code` for retry / fallback / human escalation.
export class AegisError extends Error {
  readonly code: string;
  readonly remediation: string;
  readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super(payload.message);
    this.name = "AegisError";
    this.code = payload.code;
    this.remediation = payload.remediation;
    this.docs_url = payload.docs_url;
    if (payload.cause !== undefined) {
      (this as { cause?: unknown }).cause = payload.cause;
    }
  }

  toJSON(): {
    name: string;
    message: string;
    code: string;
    remediation: string;
    docs_url: string;
  } {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      remediation: this.remediation,
      docs_url: this.docs_url,
    };
  }
}

// Input validation failure — purpose / scope / denyFields / mode shape.
export class AegisValidationError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisValidationError";
  }
}

// aegis.yaml load / parse / shape error.
export class AegisConfigError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisConfigError";
  }
}

// shield/ingest response parse error — server contract violation.
export class AegisIngestError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisIngestError";
  }
}

// audit/verify response parse error — chain invariant violation.
export class AegisAuditError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisAuditError";
  }
}

// streamSession(): the boundary did not grant a stream (deny / unledgered /
// unreachable open, or a denied delegate() window). The agent block never
// ran — the fail-closed signal is this exception (a denied stream must stop
// the agent before it starts). Python parity: AegisStreamDenied.
export class AegisStreamDeniedError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;

  constructor(payload: AegisErrorPayload) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisStreamDeniedError";
  }
}

// streamSession(): the boundary revoked the stream mid-session. Carries
// `reason` (duress_active / legal_hold / delegation_expired /
// gateway_unavailable / …). Python parity: AegisStreamRevoked.
export class AegisStreamRevokedError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;
  readonly reason: string;

  constructor(payload: AegisErrorPayload & { reason: string }) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisStreamRevokedError";
    this.reason = payload.reason;
  }
}

// HTTP-level failure — non-2xx response from aegis-core REST.
export class AegisHttpError extends AegisError {
  declare readonly code: string;
  declare readonly remediation: string;
  declare readonly docs_url: string;
  readonly status: number;

  constructor(payload: AegisErrorPayload & { status: number }) {
    super({
      code: payload.code,
      remediation: payload.remediation,
      docs_url: payload.docs_url,
      message: payload.message,
      cause: payload.cause,
    });
    this.name = "AegisHttpError";
    this.status = payload.status;
  }
}

// Helper — construct a docs_url from a code under a canonical base.
const DOCS_BASE = "https://aegis-trust.dev/errors";

export function aegisDocsUrl(code: string): string {
  return `${DOCS_BASE}/${code}`;
}
