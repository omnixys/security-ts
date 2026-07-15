import {
  AuthModule,
  EventPermissionGuard,
  EventPermissionResolver,
  EventPermissions,
  EVENT_PERMISSIONS_KEY,
  EventRoleGuard,
  EventRoleResolver,
  EventRoles,
  EVENT_ROLES_KEY,
} from '../dist/index.js';
import { Test } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import assert from 'node:assert/strict';
import test from 'node:test';

class MockEventRoleResolver extends EventRoleResolver {
  async getRoleForUser(userId, eventId) {
    if (userId === 'admin-user' && eventId === 'event-1') {
      return 'admin';
    }
    return null;
  }
}

class MockEventPermissionResolver extends EventPermissionResolver {
  async getPermissionsForUser(userId, eventId) {
    if (userId === 'admin-user' && eventId === 'event-1') {
      return ['roles.manage'];
    }
    return [];
  }
}

test('AuthModule.forRoot compiles without EventRoleResolver', async () => {
  const module = await Test.createTestingModule({
    imports: [
      AuthModule.forRoot({
        issuer: 'https://example.com/realms/test',
        jwksUri: 'https://example.com/realms/test/protocol/openid-connect/certs',
      }),
    ],
  }).compile();

  const authModule = module.get(AuthModule);
  assert.ok(authModule instanceof AuthModule, 'AuthModule should be resolvable');
});

test('EventPermissionGuard is exported from package barrel', () => {
  assert.ok(typeof EventPermissionGuard === 'function', 'EventPermissionGuard is a class');
  assert.ok(
    typeof EventPermissionResolver === 'function',
    'EventPermissionResolver is a class',
  );
  assert.ok(typeof EventPermissions === 'function', 'EventPermissions is a function');
  assert.ok(typeof EVENT_PERMISSIONS_KEY === 'symbol', 'EVENT_PERMISSIONS_KEY is a symbol');
});

test('EventPermissionGuard resolves with EventPermissionResolver provider', async () => {
  const module = await Test.createTestingModule({
    providers: [
      Reflector,
      {
        provide: EventPermissionResolver,
        useClass: MockEventPermissionResolver,
      },
      EventPermissionGuard,
    ],
  }).compile();

  const guard = module.get(EventPermissionGuard);
  assert.ok(guard instanceof EventPermissionGuard, 'guard is an EventPermissionGuard');

  const resolver = module.get(EventPermissionResolver);
  assert.ok(
    resolver instanceof MockEventPermissionResolver,
    'resolver is MockEventPermissionResolver',
  );
});

test('EventRoleGuard is exported from package barrel', () => {
  assert.ok(typeof EventRoleGuard === 'function', 'EventRoleGuard is a class');
  assert.ok(typeof EventRoleResolver === 'function', 'EventRoleResolver is a class');
  assert.ok(typeof EventRoles === 'function', 'EventRoles is a function');
  assert.ok(typeof EVENT_ROLES_KEY === 'symbol', 'EVENT_ROLES_KEY is a symbol');
});

test('EventRoleGuard resolves with EventRoleResolver provider', async () => {
  const module = await Test.createTestingModule({
    providers: [
      Reflector,
      {
        provide: EventRoleResolver,
        useClass: MockEventRoleResolver,
      },
      EventRoleGuard,
    ],
  }).compile();

  const guard = module.get(EventRoleGuard);
  assert.ok(guard instanceof EventRoleGuard, 'guard is an instance of EventRoleGuard');

  const resolver = module.get(EventRoleResolver);
  assert.ok(resolver instanceof MockEventRoleResolver, 'resolver is MockEventRoleResolver');
});

test('EventRoleResolver DI token identity is stable', () => {
  const token1 = EventRoleResolver;
  const token2 = EventRoleResolver;
  assert.equal(token1, token2, 'same token reference');

  const guardProvides = { provide: EventRoleResolver, useClass: MockEventRoleResolver };
  assert.equal(guardProvides.provide, EventRoleResolver, 'token used as provider key');
});

test('EventRoleGuard construction fails without EventRoleResolver', async () => {
  await assert.rejects(
    async () => {
      await Test.createTestingModule({
        providers: [Reflector, EventRoleGuard],
      }).compile();
    },
    (err) => {
      return err.message && err.message.includes('EventRoleResolver');
    },
  );
});
