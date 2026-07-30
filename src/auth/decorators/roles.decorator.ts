import { SetMetadata } from '@nestjs/common';
import type { RealmRoleType } from '@omnixys/contracts-ts';

export const ROLES_KEY = Symbol('roles');

export function Roles(
  ...roles: RealmRoleType[]
): MethodDecorator & ClassDecorator {
  return SetMetadata(ROLES_KEY, roles);
}
