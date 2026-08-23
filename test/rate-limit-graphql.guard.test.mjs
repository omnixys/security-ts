import { RateLimitGuard } from '../dist/index.js';
import assert from 'node:assert/strict';
import test from 'node:test';

test('rate-limit guard accepts GraphQL requests without using the HTTP switch', async () => {
  let key;
  const guard = new RateLimitGuard({
    async isAllowed(candidate) {
      key = candidate;
      return { allowed: true };
    },
  });
  const request = {
    url: '/graphql',
    headers: {},
    ip: '203.0.113.8',
    socket: { remoteAddress: '203.0.113.8' },
  };
  const context = {
    getType: () => 'graphql',
    getClass: () => class TestResolver {},
    getHandler: () => function testResolver() {},
    getArgs: () => [undefined, undefined, { req: request }, undefined],
    getArgByIndex: (index) => [undefined, undefined, { req: request }][index],
    switchToHttp: () => {
      throw new Error('GraphQL must not use switchToHttp');
    },
  };

  assert.equal(await guard.canActivate(context), true);
  assert.equal(key, 'rate-limit:203.0.113.8');
});
