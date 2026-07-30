import type { EventPermissionKey } from '@omnixys/contracts-ts';

export abstract class EventPermissionResolver {
  abstract getPermissionsForUser(
    userId: string,
    eventId: string,
  ): Promise<readonly EventPermissionKey[]>;
}
