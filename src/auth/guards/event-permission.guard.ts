import {
  Injectable,
  Optional,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { getRequest } from '@omnixys/context-ts';
import type { EventPermissionKey } from '@omnixys/contracts-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

import { EventAccessDeniedException } from '../../errors/event-access-denied.exception.js';
import { RESOLVED_EVENT_ID_REQUEST_KEY } from '../decorators/current-event-id.decorator.js';
import { EVENT_PERMISSIONS_KEY } from '../decorators/event-permissions.decorator.js';
import { extractEventId } from '../utils/extract-event-id.util.js';
import { EventPermissionResolver } from './event-permission-resolver.js';

function hasEveryEventPermission(
  actual: Iterable<string>,
  required: readonly string[],
): boolean {
  const actualSet = new Set(actual);
  return required.every((permission) => actualSet.has(permission));
}

@Injectable()
export class EventPermissionGuard implements CanActivate {
  private readonly fallbackReflector = new Reflector();
  private readonly log;

  constructor(
    @Optional() private readonly reflector: Reflector | undefined,
    private readonly resolver: EventPermissionResolver,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const reflector = this.reflector ?? this.fallbackReflector;
    const requiredPermissions = reflector.getAllAndOverride<
      EventPermissionKey[]
    >(EVENT_PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredPermissions?.length) {
      return true;
    }

    const req = getRequest(context);
    const user = req.user;

    if (!user) {
      this.log?.error('Event permission denied: unauthenticated');
      throw new EventAccessDeniedException({
        reason: 'unauthenticated',
      });
    }

    const eventId = extractEventId(req);

    if (!eventId) {
      this.log?.error(
        `Event permission denied: missing eventId for user ${user.id}`,
      );
      throw new EventAccessDeniedException({
        reason: 'event-id-missing',
        userId: user.id,
      });
    }

    (req as unknown as Record<string, unknown>)[RESOLVED_EVENT_ID_REQUEST_KEY] =
      eventId;

    const actualPermissions = await this.resolver.getPermissionsForUser(
      user.id,
      eventId,
    );

    if (!hasEveryEventPermission(actualPermissions, requiredPermissions)) {
      this.log?.error(
        `Event permission denied: mismatch (user=${user.id}, event=${eventId}, required=${requiredPermissions.join(',')})`,
      );

      throw new EventAccessDeniedException({
        eventId,
        userId: user.id,
        reason: 'event-permission-mismatch',
        actualPermissions,
        requiredPermissions,
      });
    }

    return true;
  }
}
