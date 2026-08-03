import {
  InvalidCredentialsException,
  JwtStrategy,
  resolveCurrentUser,
  SecurityPrincipalResolver,
  UnauthorizedTenantException,
} from '../dist/index.js';
import { ContextAccessor } from '@omnixys/context-ts';
import assert from 'node:assert/strict';
import test from 'node:test';

test('maps only verified identity metadata into PrincipalContext', () => {
  const resolver = new SecurityPrincipalResolver();
  const principal = resolver.fromVerifiedJwt(
    {
      sub: 'subject-1',
      tenant_ids: ['tenant-1'],
      sid: 'session-1',
      acr: 'mfa',
      iat: 1_700_000_000,
    },
    ['admin'],
    undefined,
    'tenant-1',
  );

  assert.deepEqual(principal, {
    subject: 'subject-1',
    actorId: 'subject-1',
    userId: 'subject-1',
    tenantId: 'tenant-1',
    roles: ['admin'],
    sessionId: 'session-1',
    authStrength: 'mfa',
    authenticatedAtEpochMs: 1_700_000_000_000,
  });
  assert.equal('accessToken' in principal, false);
  assert.equal('raw' in principal, false);
});

test('does not interpret Keycloak azp as a tenant', () => {
  const resolver = new SecurityPrincipalResolver();
  const principal = resolver.fromVerifiedJwt(
    { sub: 'subject-1', azp: 'frontend-client' },
    [],
  );

  assert.equal(principal.tenantId, undefined);
});

test('prefers auth_time and accepts Keycloak session_state metadata', () => {
  const resolver = new SecurityPrincipalResolver();
  const principal = resolver.fromVerifiedJwt(
    {
      sub: 'subject-1',
      session_state: 'session-state-1',
      auth_time: 1_700_000_050,
      iat: 1_700_000_100,
      acr: 'urn:mfa',
    },
    [],
  );

  assert.equal(principal.sessionId, 'session-state-1');
  assert.equal(principal.authStrength, 'urn:mfa');
  assert.equal(principal.authenticatedAtEpochMs, 1_700_000_050_000);
});

test('uses only a configured verified tenant claim', () => {
  const resolver = new SecurityPrincipalResolver();
  const principal = resolver.fromVerifiedJwt(
    {
      sub: 'subject-1',
      tenant_ids: ['ignored-default'],
      organization_id: 'trusted-organization',
    },
    [],
    'organization_id',
  );

  assert.equal(principal.tenantId, 'trusted-organization');
});

test('rejects a verified token whose header tenant is not in tenant_ids', () => {
  ContextAccessor.run(
    {
      requestId: 'request-1',
      correlationId: 'correlation-1',
      actorId: 'actor-1',
      tenantId: 'tenant-context',
      traceId: 'trace-1',
    },
    () => {
      const resolver = new SecurityPrincipalResolver();

      assert.throws(
        () =>
          resolver.fromVerifiedJwt(
            {
              sub: 'subject-1',
              tenant_ids: ['tenant-a', 'tenant-b'],
            },
            [],
            undefined,
            'tenant-c',
          ),
        (error) => {
          assert.ok(error instanceof UnauthorizedTenantException);
          assert.equal(error.code, 'UNAUTHORIZED_TENANT');
          assert.equal(error.requestId, 'request-1');
          assert.equal(error.correlationId, 'correlation-1');
          assert.equal(error.traceId, 'trace-1');
          assert.equal(error.actorId, 'actor-1');
          assert.equal(error.tenantId, 'tenant-context');
          return true;
        },
      );
    },
  );
});

test('JwtStrategy preserves its legacy user result and adds contextPrincipal', async () => {
  const strategy = new JwtStrategy({
    issuer: 'https://identity.example.com/realms/test',
    jwksUri: 'https://identity.example.com/realms/test/certs',
  });
  const payload = {
    sub: 'subject-1',
    preferred_username: 'tester',
    email: 'tester@example.com',
    tenant_ids: ['tenant-1'],
    realm_access: { roles: ['admin'] },
  };

  const user = await strategy.validate(
    { headers: { 'x-tenant-id': 'tenant-1' } },
    payload,
  );

  assert.equal(user.id, 'subject-1');
  assert.equal(user.username, 'tester');
  assert.equal(user.email, 'tester@example.com');
  assert.equal(user.raw, payload);
  assert.equal(user.contextPrincipal.subject, 'subject-1');
  assert.equal(user.contextPrincipal.tenantId, 'tenant-1');
});

test('JwtStrategy rejects a verified token without a principal subject', async () => {
  const strategy = new JwtStrategy({
    issuer: 'https://identity.example.com/realms/test',
    jwksUri: 'https://identity.example.com/realms/test/certs',
  });

  await assert.rejects(
    strategy.validate({ headers: {} }, { realm_access: { roles: [] } }),
    InvalidCredentialsException,
  );
});

test('CurrentUser supports bearer-authenticated requests without cookies', () => {
  const raw = {
    sub: 'subject-1',
    preferred_username: 'tester',
    email: 'tester@example.com',
    given_name: 'Test',
    family_name: 'User',
    realm_access: { roles: ['USER'] },
  };
  const current = resolveCurrentUser({
    user: {
      ...raw,
      raw,
    },
  });

  assert.equal(current.id, 'subject-1');
  assert.equal(current.username, 'tester');
  assert.equal(current.access_token, undefined);
  assert.equal(current.refresh_token, undefined);
});
