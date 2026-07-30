import {
  Injectable,
  Logger,
  Optional,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { EventRoleType } from '@omnixys/contracts-ts';
import { getRequest } from '@omnixys/context-ts';

import { EventAccessDeniedException } from '../../errors/event-access-denied.exception.js';
import { RESOLVED_EVENT_ID_REQUEST_KEY } from '../decorators/current-event-id.decorator.js';
import { EVENT_ROLES_KEY } from '../decorators/event-roles.decorator.js';
import { EventRoleResolver } from './event-role-resolver.js';
import { extractEventId } from '../utils/extract-event-id.util.js';

@Injectable()
export class EventRoleGuard implements CanActivate {
  private readonly logger = new Logger(EventRoleGuard.name);
  private readonly fallbackReflector = new Reflector();

  constructor(
    @Optional() private readonly reflector: Reflector | undefined,
    private readonly resolver: EventRoleResolver,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const reflector = this.reflector ?? this.fallbackReflector;
    const requiredRoles =
      reflector.getAllAndOverride<EventRoleType[]>(
        EVENT_ROLES_KEY,
        [context.getHandler(), context.getClass()],
      );

    if (!requiredRoles?.length) {
      return true;
    }

    const req = getRequest(context);
    const user = req.user;

    if (!user) {
      this.logger.warn('Event authorization denied: unauthenticated');

      throw new EventAccessDeniedException({
        reason: 'unauthenticated',
      });
    }

    const eventId = extractEventId(req);

    if (!eventId) {
      this.logger.warn(
        `Event authorization denied: missing eventId for user ${user.id}`,
      );

      throw new EventAccessDeniedException({
        reason: 'event-id-missing',
        userId: user.id,
      });
    }

    (req as unknown as Record<string, unknown>)[
      RESOLVED_EVENT_ID_REQUEST_KEY
    ] = eventId;

    const role = await this.resolver.getRoleForUser(
      user.id,
      eventId,
    );

    if (!role) {
      this.logger.warn(
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
      this.logger.warn(
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
