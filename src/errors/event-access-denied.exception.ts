import { ForbiddenException } from '@nestjs/common';
import { ErrorCode } from '@omnixys/contracts';
import {
  errorDetails,
  type SecurityErrorMetadata,
} from './security.exception.js';
import type { EventRoleType } from '@omnixys/contracts';
import type { EventPermissionKey } from '@omnixys/contracts';

export type EventAccessDeniedReason =
  | 'unauthenticated'
  | 'event-id-missing'
  | 'event-role-not-found'
  | 'event-role-mismatch'
  | 'event-permission-mismatch';

export class EventAccessDeniedException extends ForbiddenException {
  readonly code = ErrorCode.EVENT_ACCESS_DENIED;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(params: {
    eventId?: string;
    reason: EventAccessDeniedReason;
    userId?: string;
    actualRole?: EventRoleType | null;
    requiredRoles?: EventRoleType[];
    actualPermissions?: readonly EventPermissionKey[];
    requiredPermissions?: readonly EventPermissionKey[];
  }) {
    const details = errorDetails(
      ErrorCode.EVENT_ACCESS_DENIED,
      'Event access denied',
      {
        eventId: params.eventId ?? 'unknown',
        reason: params.reason,
        userId: params.userId,
        actualRole: params.actualRole,
        requiredRoles: params.requiredRoles,
        actualPermissions: params.actualPermissions,
        requiredPermissions: params.requiredPermissions,
      },
    );

    super(details);
    Object.assign(this, details);
  }
}
