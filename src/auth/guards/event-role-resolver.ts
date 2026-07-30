import type { EventRoleType } from '@omnixys/contracts-ts';

export abstract class EventRoleResolver {
  abstract getRoleForUser(
    userId: string,
    eventId: string,
  ): Promise<EventRoleType | null>;
}
