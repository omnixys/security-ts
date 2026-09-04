import { SECURITY_OPTIONS } from '../security.constants.js';
import { RateLimitStore } from './rate-limit.store.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { CacheObservabilityService } from '@omnixys/observability-ts';

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds?: number;
  remaining?: number;
  resetAt?: number; // epoch ms
}

interface AttributeSpan {
  setAttribute(name: string, value: string | number | boolean): unknown;
}

@Injectable()
export class RateLimitService {
    private readonly logger;

  constructor(
    @Inject(SECURITY_OPTIONS) private readonly options: any,
    @Optional()
    @Inject('RATE_LIMIT_STORE')
    readonly cache?: RateLimitStore,
    @Optional()
    private readonly observability?: CacheObservabilityService,
    @Optional()
    private readonly loggerService?: OmnixysLogger,
  ) {
    this.logger = this.loggerService?.log(RateLimitService.name, 'package:@omnixys/security-ts');
  }

  async isAllowed(key: string): Promise<RateLimitResult> {
    this.logger?.debug('RateLimit key=%s', key);
    const operation = async (span?: AttributeSpan) => {
      if (!this.options.rateLimit?.enabled) return { allowed: true };
      if (!this.cache) {
        this.logger?.error('Rate limiting store is not configured', { reason: 'missing_store' });
        throw new Error('Rate limiting is enabled but no rateLimitStore is configured');
      }

      const limit = this.options.rateLimit.defaultLimit ?? 100;
      const windowMs = this.options.rateLimit.defaultWindowMs ?? 60000;
      const windowSeconds = Math.ceil(windowMs / 1000);

      const current = await this.cache.incr(key);

      this.logger?.debug(
  'RateLimit current=%d limit=%d key=%s',
  current,
  limit,
  key,
);

      if (current === 1) {
        await this.cache.expire(key, windowSeconds);
      }

      const ttl = await this.cache.ttl(key);

      this.logger?.debug(
  'key=%s current=%d ttl=%d',
  key,
  current,
  ttl,
);

      const remaining = Math.max(limit - current, 0);
      const allowed = current <= limit;

      span?.setAttribute('rate_limit.key', key);
      span?.setAttribute('rate_limit.limit', limit);
      span?.setAttribute('rate_limit.ttl_seconds', windowSeconds);
      span?.setAttribute('rate_limit.current', current);
      span?.setAttribute('rate_limit.allowed', current <= limit);
      span?.setAttribute('rate_limit.remaining', remaining);
      if (!allowed) {
        span?.setAttribute('rate_limit.retry_after', ttl);
      }

      if (!allowed) {
        this.logger?.child(RateLimitService.name).warn('Rate limit exceeded', {
          key,
          limit,
          retryAfterSeconds: ttl > 0 ? ttl : windowSeconds,
        });
        return {
          allowed,
          retryAfterSeconds: ttl > 0 ? ttl : windowSeconds,
          remaining: 0,
          resetAt: Date.now() + (ttl > 0 ? ttl * 1000 : windowMs),
        };
      }

      return {
        allowed: true,
        remaining,
        resetAt: Date.now() + (ttl > 0 ? ttl * 1000 : windowMs),
      };
    };

    return this.observability
      ? this.observability.trace('rate_limit.hit', key, operation)
      : operation(undefined);
  }
}
