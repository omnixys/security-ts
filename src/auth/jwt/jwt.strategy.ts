import { InvalidCredentialsException } from '../../errors/security.exception.js';
import type { SecurityJwtOptions } from '../../types/security.types.js';
import { SecurityPrincipalResolver } from '../context/security-principal.resolver.js';
import { extractUserRoles } from '../utils/extract-roles.util.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { OMNIXYS_USER_ID_CLAIM } from '@omnixys/contracts-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';
import jwksRsa from 'jwks-rsa';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly log;

  constructor(
    @Inject('JWT_OPTIONS')
    private readonly options: SecurityJwtOptions,
    @Optional()
    private readonly principalResolver: SecurityPrincipalResolver = new SecurityPrincipalResolver(),
    @Optional()
    private readonly logger?: OmnixysLogger,
  ) {
    super({
      algorithms: ['RS256'],
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      issuer: options.issuer,
      audience: options.audience,
      passReqToCallback: true,

      secretOrKeyProvider: jwksRsa.passportJwtSecret({
        cache: true,
        cacheMaxEntries: 5,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        jwksUri: options.jwksUri,
      }),
    });
    this.log = this.logger?.log(this.constructor.name);
  }

  async validate(request: any, payload: any) {
    const roles = extractUserRoles(payload);
    const headerTenantId = firstStringHeader(request?.headers?.['x-tenant-id']);
    const contextPrincipal = this.principalResolver.fromVerifiedJwt(
      payload,
      roles,
      this.options.tenantClaim,
      headerTenantId,
    );
    if (!contextPrincipal) {
      this.log?.error('Verified token has no subject', {
        reason: 'missing_subject',
      });
      throw new InvalidCredentialsException('Verified token has no subject', {
        reason: 'missing_subject',
      });
    }

    // The HTTP user-auth path only yields USER tokens (fail-closed without the
    // `omnixys_user_id` claim). `id` must always be the internal U — never the
    // Keycloak subject (K). If a SERVICE token ever reaches this strategy, its
    // userId is absent, so it must be rejected instead of aliasing actorId=K.
    if (!contextPrincipal.userId) {
      this.log?.error('Verified token carries no internal user id', {
        reason: 'missing_user_claim',
        principalType: contextPrincipal.principalType,
      });
      throw new InvalidCredentialsException(
        'Verified token carries no internal user id',
        { reason: 'missing_user_claim' },
      );
    }

    return {
      id: contextPrincipal.userId,
      username: payload.preferred_username,
      email: payload.email,
      roles,
      raw: payload,
      contextPrincipal,
    };
  }
}

function firstStringHeader(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) return value;
  if (!Array.isArray(value)) return undefined;
  return value.find((entry): entry is string => typeof entry === 'string');
}
