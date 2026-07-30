import { UnauthorizedTenantException } from '../../errors/security.exception.js';
import type {
  PrincipalContext,
  PrincipalResolutionInput,
  PrincipalResolver,
} from '@omnixys/context-ts';

export interface VerifiedJwtPrincipalClaims {
  readonly [claim: string]: unknown;
  readonly sub?: unknown;
  readonly tenant_id?: unknown;
  readonly tenantId?: unknown;
  readonly sid?: unknown;
  readonly session_state?: unknown;
  readonly acr?: unknown;
  readonly auth_time?: unknown;
  readonly iat?: unknown;
}

/**
 * Converts the result of successful token verification into transport-neutral
 * principal metadata. This class never verifies or decodes a token itself.
 */
export class SecurityPrincipalResolver implements PrincipalResolver {
  resolve(input: PrincipalResolutionInput): PrincipalContext | undefined {
    return isPrincipalContext(input.verifiedPrincipal)
      ? input.verifiedPrincipal
      : undefined;
  }

  fromVerifiedJwt(
    claims: VerifiedJwtPrincipalClaims,
    roles: readonly string[],
    tenantClaim?: string,
  ): PrincipalContext | undefined {
    const subject = stringClaim(claims.sub);
    if (!subject) return undefined;

    const tenantId = resolveTenantClaim(claims, tenantClaim);
    const authenticatedAt = numericDateClaim(claims.auth_time ?? claims.iat);

    return {
      subject,
      actorId: subject,
      userId: subject,
      tenantId,
      roles: [...roles],
      sessionId: stringClaim(claims.sid) ?? stringClaim(claims.session_state),
      authStrength: stringClaim(claims.acr),
      authenticatedAtEpochMs: authenticatedAt,
    };
  }
}

function resolveTenantClaim(
  claims: VerifiedJwtPrincipalClaims,
  configuredClaim?: string,
): string | undefined {
  if (configuredClaim) return stringClaim(claims[configuredClaim]);

  const snakeCase = stringClaim(claims.tenant_id);
  const camelCase = stringClaim(claims.tenantId);
  if (snakeCase && camelCase && snakeCase !== camelCase) {
    throw new UnauthorizedTenantException(
      'Verified token has conflicting tenant claims',
      {
        claimNames: ['tenant_id', 'tenantId'],
      },
    );
  }

  return snakeCase ?? camelCase;
}

function numericDateClaim(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value * 1_000
    : undefined;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function isPrincipalContext(value: unknown): value is PrincipalContext {
  if (!isRecord(value)) return false;
  return (
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    Array.isArray(value.roles) &&
    value.roles.every((role) => typeof role === 'string')
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
