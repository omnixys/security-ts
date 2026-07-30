import { RateLimitService } from './rate-limit.service.js';
import { RateLimitExceededException } from '../errors/security.exception.js';
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { getIp } from '@omnixys/context-ts';

@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(private readonly rateLimit: RateLimitService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ip = getIp(context);

    const key = `rate-limit:${ip}`; // oder userId

    const allowed = await this.rateLimit.isAllowed(key);

    if (allowed.allowed === false) {
      throw new RateLimitExceededException({
        message: 'Too many requests. Please try again later.',
        retryAfterSeconds: allowed.retryAfterSeconds,
      });
    }

    return true;
  }
}
