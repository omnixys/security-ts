import { ForbiddenOperationException } from '../../errors/security.exception.js';
import { ROLES_KEY } from '../decorators/roles.decorator.js';
import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  Optional,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { getRequest } from '@omnixys/context-ts';
import type { RealmRoleType } from '@omnixys/contracts-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class RoleGuard implements CanActivate {
  private readonly fallbackReflector = new Reflector();
  private readonly log;

  constructor(
    @Optional() private readonly reflector: Reflector | undefined,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
  }

  canActivate(context: ExecutionContext): boolean {
    const reflector = this.reflector ?? this.fallbackReflector;
    const requiredRoles =
      reflector.getAllAndOverride<RealmRoleType[]>(ROLES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    if (requiredRoles.length === 0) {
      return true;
    }

    const req = getRequest(context);

    const user = req.user;

    if (!user) {
      this.log?.error('Role authorization denied', {
        reason: 'unauthenticated',
        requiredRoles,
      });
      throw new ForbiddenOperationException('User not authenticated', {
        reason: 'unauthenticated',
        requiredRoles,
      });
    }

    const roles = user.roles ?? [];

    const allowed = requiredRoles.some((role) => roles.includes(role));

    if (!allowed) {
      this.log?.error('Role authorization denied', {
        reason: 'missing_role',
        requiredRoles,
      });
      throw new ForbiddenOperationException('Insufficient permissions', {
        reason: 'missing-role',
        requiredRoles,
      });
    }

    return true;
  }
}
