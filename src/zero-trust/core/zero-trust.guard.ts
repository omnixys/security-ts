import {
  AccessBlockedException,
  StepUpRequiredException,
} from '../error/zero-trust.exception.js';
import { ZeroTrustService } from './zero-trust.service.js';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Optional,
} from '@nestjs/common';
import { ContextAccessor, getRequest } from '@omnixys/context-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class ZeroTrustGuard implements CanActivate {
  constructor(
    private readonly zeroTrust: ZeroTrustService,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = getRequest(context);
    const user = req.user;
    const canonical = ContextAccessor.get();

    if (!user) {
      this.logger
        ?.child(ZeroTrustGuard.name)
        .warn('Zero-trust evaluation denied', {
          reason: 'unauthenticated',
        });
      return false;
    }

    const result = await this.zeroTrust.evaluate({
      userId: canonical?.principal?.userId ?? user.id,
      ip: canonical?.client?.ip ?? req?.ip,
      userAgent: canonical?.client?.userAgent ?? req?.headers?.['user-agent'],
      acceptLanguage:
        canonical?.client?.locale ?? req?.headers?.['accept-language'],
      clientDeviceId: canonical?.client?.deviceId ?? req?.cookies?.device_id,
      isPasswordless: false,
      isResetFlow: false,
    });

    if (result.decision === 'BLOCK') {
      this.logger
        ?.child(ZeroTrustGuard.name)
        .warn('Zero-trust access blocked', {
          reasons: result.reasons,
          riskScore: result.score,
        });
      throw new AccessBlockedException(result.reasons);
    }

    if (result.decision === 'STEP_UP') {
      this.logger
        ?.child(ZeroTrustGuard.name)
        .warn('Zero-trust step-up required', {
          method: result.stepUp,
          reasons: result.reasons,
          riskScore: result.score,
        });
      throw new StepUpRequiredException(result.stepUp!, result.reasons);
    }

    return true;
  }
}
