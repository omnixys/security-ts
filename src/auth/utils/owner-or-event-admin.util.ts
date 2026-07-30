import { EventRoleType } from '@omnixys/contracts-ts';

export function isOwnerOrEventAdmin(
  resourceOwnerId: string,
  currentUserId: string,
  eventRole: EventRoleType | null,
): boolean {
  return resourceOwnerId === currentUserId || eventRole === EventRoleType.ADMIN;
}
