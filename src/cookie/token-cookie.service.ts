import { SECURITY_OPTIONS } from '../security.constants.js';
import type { SecurityModuleOptions } from '../types/security.types.js';
import { CookieService } from './cookie.service.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import type { FastifyReply } from 'fastify';

export interface TokenCookieValues {
  readonly accessToken: string;
  readonly refreshToken: string;
}

export interface TokenCookieLifetimeOverrides {
  readonly accessTokenMaxAgeMs?: number;
  readonly refreshTokenMaxAgeMs?: number;
}

/** Security-owned policy for distinct access-token and refresh-token cookies. */
@Injectable()
export class TokenCookieService {
  private readonly log;

  constructor(
    @Inject(SECURITY_OPTIONS)
    private readonly options: SecurityModuleOptions,
    private readonly cookies: CookieService,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
  }

  setTokens(
    reply: FastifyReply,
    values: TokenCookieValues,
    lifetimes: TokenCookieLifetimeOverrides = {},
  ): void {
    const options = this.options.cookie;

    reply.setCookie(
      options?.accessTokenName ?? 'access_token',
      values.accessToken,
      this.cookieOptions(lifetimes.accessTokenMaxAgeMs ?? options?.accessTokenMaxAgeMs),
    );
    reply.setCookie(
      options?.refreshTokenName ?? 'refresh_token',
      values.refreshToken,
      this.cookieOptions(lifetimes.refreshTokenMaxAgeMs ?? options?.refreshTokenMaxAgeMs),
    );
  }

  clearTokens(reply: FastifyReply): void {
    const options = this.options.cookie;
    const cookieOptions = this.cookies.getDefaults();

    reply.clearCookie(options?.accessTokenName ?? 'access_token', cookieOptions);
    reply.clearCookie(options?.refreshTokenName ?? 'refresh_token', cookieOptions);
  }

  private cookieOptions(maxAgeMs: number | undefined) {
    if (maxAgeMs !== undefined && (!Number.isFinite(maxAgeMs) || maxAgeMs < 0)) {
      this.log?.error('Token cookie policy rejected', { reason: 'invalid_max_age' });
      throw new RangeError('Token cookie maxAgeMs must be a finite non-negative value');
    }

    return {
      ...this.cookies.getDefaults(),
      // @fastify/cookie serializes maxAge in seconds.
      maxAge: maxAgeMs === undefined ? undefined : Math.ceil(maxAgeMs / 1_000),
    };
  }
}
