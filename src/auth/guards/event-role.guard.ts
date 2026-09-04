import {
  Injectable,
  Optional,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { getRequest } from '@omnixys/context-ts';
import { EventRoleType } from '@omnixys/contracts-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

import { EventAccessDeniedException } from '../../errors/event-access-denied.exception.js';
import { RESOLVED_EVENT_ID_REQUEST_KEY } from '../decorators/current-event-id.decorator.js';
import { EVENT_ROLES_KEY } from '../decorators/event-roles.decorator.js';
import { extractEventId } from '../utils/extract-event-id.util.js';
import { EventRoleResolver } from './event-role-resolver.js';

@Injectable()
export class EventRoleGuard implements CanActivate {
  private readonly fallbackReflector = new Reflector();
  private readonly log;

  constructor(
    @Optional() private readonly reflector: Reflector | undefined,
    private readonly resolver: EventRoleResolver,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name, 'package:@omnixys/security-ts');
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const reflector = this.reflector ?? this.fallbackReflector;
    const requiredRoles = reflector.getAllAndOverride<EventRoleType[]>(
      EVENT_ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles?.length) {
      return true;
    }

    const req = getRequest(context);
    const user = req.user;

    if (!user) {
      this.log?.error('Event authorization denied: unauthenticated');

      throw new EventAccessDeniedException({
        reason: 'unauthenticated',
      });
    }

    const eventId = extractEventId(req);

    if (!eventId) {
      this.log?.error(
        `Event authorization denied: missing eventId for user ${user.id}`,
      );

      throw new EventAccessDeniedException({
        reason: 'event-id-missing',
        userId: user.id,
      });
    }

    (req as unknown as Record<string, unknown>)[RESOLVED_EVENT_ID_REQUEST_KEY] =
      eventId;

    const role = await this.resolver.getRoleForUser(user.id, eventId);

    if (!role) {
      this.log?.error(
        `Event authorization denied: role projection missing (user=${user.id}, event=${eventId})`,
      );

      throw new EventAccessDeniedException({
        eventId,
        userId: user.id,
        reason: 'event-role-not-found',
        actualRole: null,
        requiredRoles,
      });
    }

    if (!requiredRoles.includes(role)) {
      this.log?.error(
        `Event authorization denied: role mismatch (user=${user.id}, event=${eventId}, actual=${role}, required=${requiredRoles.join(',')})`,
      );

      throw new EventAccessDeniedException({
        eventId,
        userId: user.id,
        reason: 'event-role-mismatch',
        actualRole: role,
        requiredRoles,
      });
    }

    return true;
  }
}
