import { Optional } from '@nestjs/common';
import { UnauthorizedTenantException } from '../../errors/security.exception.js';
import type {
  PrincipalContext,
  PrincipalResolutionInput,
  PrincipalResolver,
} from '@omnixys/context-ts';
import { OMNIXYS_USER_ID_CLAIM, PrincipalType } from '@omnixys/contracts-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

export interface VerifiedJwtPrincipalClaims {
  readonly [claim: string]: unknown;
  readonly sub?: unknown;
  readonly tenant_ids?: unknown;
  readonly tenantId?: unknown;
  readonly sid?: unknown;
  readonly session_state?: unknown;
  readonly acr?: unknown;
  readonly auth_time?: unknown;
  readonly iat?: unknown;
}

export interface PrincipalTypeHint {
  /**
   * Explicitly declares the principal kind when the caller already knows the
   * token is a service/machine token (e.g. an OAuth client / MCP client token).
   * When omitted, the resolver classifies USER tokens by the presence of the
   * `omnixys_user_id` claim and fails closed (returns undefined) for any token
   * that carries neither a user U claim nor an explicit SERVICE hint.
   */
  readonly principalType?: PrincipalType;
}

/**
 * Converts the result of successful token verification into transport-neutral
 * principal metadata. This class never verifies or decodes a token itself.
 */
export class SecurityPrincipalResolver implements PrincipalResolver {
  private readonly log;

    constructor(
      @Optional()
      private readonly logger?: OmnixysLogger,
    ) {
      this.log = this.logger?.log(this.constructor.name, 'package:@omnixys/security-ts');
    }
  

  resolve(input: PrincipalResolutionInput): PrincipalContext | undefined {
    return isPrincipalContext(input.verifiedPrincipal)
      ? input.verifiedPrincipal
      : undefined;
  }

  fromVerifiedJwt(
    claims: VerifiedJwtPrincipalClaims,
    roles: readonly string[],
    tenantClaim?: string,
    headerTenantId?: string,
    hint?: PrincipalTypeHint,
  ): PrincipalContext | undefined {
    this.log?.debug('claims: %o', claims);
    const subject = stringClaim(claims.sub);
    if (!subject) return undefined;

    const tenantId = resolveTenantClaim(claims, tenantClaim, headerTenantId);
    const authenticatedAt = numericDateClaim(claims.auth_time ?? claims.iat);

    const userId = stringClaim(claims[OMNIXYS_USER_ID_CLAIM]);

    if (userId) {
      return {
        subject,
        principalType: PrincipalType.USER,
        userId,
        actorId: userId,
        tenantId,
        roles: [...roles],
        sessionId: stringClaim(claims.sid) ?? stringClaim(claims.session_state),
        authStrength: stringClaim(claims.acr),
        authenticatedAtEpochMs: authenticatedAt,
      };
    }

    if (hint?.principalType === PrincipalType.SERVICE) {
      // Transitional compatibility path (Phase 4 Teil 0): machine / service /
      // agent principal is NOT a user and must never receive a fabricated U.
      // TODO(arch): introduce a dedicated Service-Principal domain (S = UUIDv7)
      // with serviceId = S, actorId = S and stop aliasing actorId = subject.
      return {
        subject,
        principalType: PrincipalType.SERVICE,
        actorId: subject,
        tenantId,
        roles: [...roles],
        sessionId: stringClaim(claims.sid) ?? stringClaim(claims.session_state),
        authStrength: stringClaim(claims.acr),
        authenticatedAtEpochMs: authenticatedAt,
      };
    }

    // Fail-closed: a token that is neither a user token (no omnixys_user_id
    // claim) nor an explicitly-declared service token is rejected.
    return undefined;
  }
}

function resolveTenantClaim(
  claims: VerifiedJwtPrincipalClaims,
  configuredClaim?: string,
  headerTenantId?: string,
): string | undefined {
  if (configuredClaim) return stringClaim(claims[configuredClaim]);

  const tenantIds = stringListClaim(claims.tenant_ids);
  if (tenantIds.length > 0) {
    if (headerTenantId && tenantIds.includes(headerTenantId)) {
      return headerTenantId;
    }
    throw new UnauthorizedTenantException(
      'Verified token does not grant access to the requested tenant',
      {
        claimNames: ['tenant_ids'],
      },
    );
  }

  const camelCase = stringListClaim(claims.tenantId);
  return camelCase[0];
}

function numericDateClaim(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value * 1_000
    : undefined;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function stringListClaim(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  const single = stringClaim(value);
  return single ? [single] : [];
}

function isPrincipalContext(value: unknown): value is PrincipalContext {
  if (!isRecord(value)) return false;
  return (
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    (value.principalType === PrincipalType.USER ||
      value.principalType === PrincipalType.SERVICE) &&
    Array.isArray(value.roles) &&
    value.roles.every((role) => typeof role === 'string')
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
