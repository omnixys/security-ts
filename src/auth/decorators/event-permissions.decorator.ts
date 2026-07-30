import { SetMetadata } from '@nestjs/common';
import type { EventPermissionKey } from '@omnixys/contracts-ts';

export const EVENT_PERMISSIONS_KEY = Symbol('event_permissions');

export function EventPermissions(
  ...permissions: EventPermissionKey[]
): MethodDecorator & ClassDecorator {
  return SetMetadata(EVENT_PERMISSIONS_KEY, permissions);
}
