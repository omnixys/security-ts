import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CONTEXT_TENANT_VERIFIER } from '@omnixys/context-ts';
import { GrpcClientModule } from '@omnixys/grpc-ts/clients';
import { fileURLToPath } from 'node:url';

import { AuthModule } from './auth/auth.module.js';
import { JweModule } from './jwe/jwe.module.js';

import {
  SECURITY_OPTIONS,
  TENANT_GRPC_CLIENT,
  TENANT_VERIFICATION_OPTIONS,
} from './security.constants.js';
import type { SecurityModuleOptions } from './types/security.types.js';

import { TenantVerifierService } from './tenant/tenant-verifier.service.js';

import { CookieService } from './cookie/cookie.service.js';
import { TokenCookieService } from './cookie/token-cookie.service.js';
import { SecurityAuditService } from './distributed/audit.service.js';
import { TokenRevocationService } from './distributed/revocation.service.js';
import { RateLimitService } from './rate-limit/rate-limit.service.js';
import { SecureSessionService } from './session/secure-session.service.js';

import { HeaderAuthGuard } from './auth/guards/header-auth.guard.js';
import { RoleGuard } from './auth/guards/role.guard.js';
import { HashModule } from './hash/hash.module.js';
import { RateLimitGuard } from './rate-limit/rate-limit.guard.js';
import { ZeroTrustGuard } from './zero-trust/core/zero-trust.guard.js';
import { FingerprintService } from './zero-trust/index.js';
import { ZeroTrustModule } from './zero-trust/zero-trust.module.js';

@Global()
@Module({})
export class SecurityModule {
  static forRoot(options: SecurityModuleOptions): DynamicModule {
    const optionsProvider: Provider = {
      provide: SECURITY_OPTIONS,
      useValue: options,
    };
    const providers: Provider[] = [
      optionsProvider,
      SecureSessionService,
      RateLimitService,
      CookieService,
      TokenCookieService,
      FingerprintService,
      {
        provide: 'FINGERPRINT_SECRET',
        useValue: options.fingerprintSecret || 'default-secret',
      },
    ];

    const distributedProviders: Provider[] = [];

    if (options.distributed?.revocationStore) {
      distributedProviders.push({
        provide: 'REVOCATION_STORE',
        useValue: options.distributed.revocationStore,
      });
      distributedProviders.push(TokenRevocationService);
    }

    if (options.distributed?.auditProducer) {
      distributedProviders.push({
        provide: 'AUDIT_PRODUCER',
        useValue: options.distributed.auditProducer,
      });
      distributedProviders.push(SecurityAuditService);
    }

    if (options.rateLimit?.rateLimitStore) {
      providers.push({
        provide: 'RATE_LIMIT_STORE',
        useValue: options.rateLimit.rateLimitStore,
      });
    }

    const globalGuards: Provider[] = options.globalGuards
      ? [
          { provide: APP_GUARD, useClass: HeaderAuthGuard },
          { provide: APP_GUARD, useClass: RoleGuard },
          { provide: APP_GUARD, useClass: ZeroTrustGuard },
        ]
      : [];

    const gloabalRateLimitGuard: Provider[] = options.rateLimit?.enabled
      ? [{ provide: APP_GUARD, useClass: RateLimitGuard }]
      : [];

    const tenantVerificationProviders: Provider[] = [];
    const tenantVerificationImports: unknown[] = [];

    if (options.tenantVerification) {
      tenantVerificationImports.push(
        GrpcClientModule.register(
          {
            package: 'omnixys.tenant',
            protoPath: fileURLToPath(
              import.meta.resolve('@omnixys/grpc-ts/proto/tenant.proto'),
            ),
            url: options.tenantVerification.url,
          },
          TENANT_GRPC_CLIENT,
        ),
      );
      tenantVerificationProviders.push(
        {
          provide: TENANT_VERIFICATION_OPTIONS,
          useValue: options.tenantVerification,
        },
        { provide: CONTEXT_TENANT_VERIFIER, useClass: TenantVerifierService },
      );
    }

    return {
      module: SecurityModule,
      imports: [
        AuthModule.forRoot(options.jwt),
        JweModule.forRoot(options.jwe || { keys: [] }),
        ZeroTrustModule.forRoot(options.zeroTrust ?? {}),
        HashModule.forRoot(options?.hash || {}),
        ...(options?.rateLimit?.imports ?? []),
        ...tenantVerificationImports,
      ],
      providers: [
        ...providers,
        ...distributedProviders,
        ...globalGuards,
        ...gloabalRateLimitGuard,
        ...tenantVerificationProviders,
      ],
      exports: [
        AuthModule,
        ZeroTrustModule,
        SecureSessionService,
        RateLimitService,
        CookieService,
        TokenCookieService,
        FingerprintService,
        ...(options.distributed?.revocationStore ? [TokenRevocationService] : []),
        ...(options.distributed?.auditProducer ? [SecurityAuditService] : []),
        ...(options.tenantVerification ? [CONTEXT_TENANT_VERIFIER] : []),
      ],
    };
  }
}
