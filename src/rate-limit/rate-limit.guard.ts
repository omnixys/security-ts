import { RateLimitExceededException } from '../errors/security.exception.js';
import { RateLimitService } from './rate-limit.service.js';
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Optional,
} from '@nestjs/common';
import { getIp, getRequest } from '@omnixys/context-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly log;

  constructor(
    private readonly rateLimit: RateLimitService,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name, 'package:@omnixys/security-ts');
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = getRequest(context);
    if (request.url?.startsWith('/health')) return true;

    const ip = getIp(context);

    const key = `rate-limit:${ip}`; // oder userId

    const allowed = await this.rateLimit.isAllowed(key);

    if (allowed.allowed === false) {
      this.log?.error('Rate limit exceeded for client', {
        ip,
        retryAfterSeconds: allowed.retryAfterSeconds,
      });
      throw new RateLimitExceededException({
        message: 'Too many requests. Please try again later.',
        retryAfterSeconds: allowed.retryAfterSeconds,
      });
    }

    return true;
  }
}
