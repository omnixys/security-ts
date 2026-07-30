import { InvalidCredentialsException } from '../../errors/security.exception.js';
import type { SecurityJwtOptions } from '../../types/security.types.js';
import { SecurityPrincipalResolver } from '../context/security-principal.resolver.js';
import { extractUserRoles } from '../utils/extract-roles.util.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { OmnixysLogger } from '@omnixys/logger-ts';
import jwksRsa from 'jwks-rsa';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
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

      secretOrKeyProvider: jwksRsa.passportJwtSecret({
        cache: true,
        cacheMaxEntries: 5,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        jwksUri: options.jwksUri,
      }),
    });
  }

  async validate(payload: any) {
    const roles = extractUserRoles(payload);
    const contextPrincipal = this.principalResolver.fromVerifiedJwt(
      payload,
      roles,
      this.options.tenantClaim,
    );
    if (!contextPrincipal) {
      this.logger
        ?.child(JwtStrategy.name)
        .warn('Verified token has no subject', {
          reason: 'missing_subject',
        });
      throw new InvalidCredentialsException('Verified token has no subject', {
        reason: 'missing_subject',
      });
    }

    return {
      id: payload.sub,
      username: payload.preferred_username,
      email: payload.email,
      roles,
      raw: payload,
      contextPrincipal,
    };
  }
}
