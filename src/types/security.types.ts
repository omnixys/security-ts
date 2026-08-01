import type { JweModuleOptions } from '../jwe/jwe.module.js';
import type { TenantVerificationOptions } from '../tenant/tenant-verifier.service.js';
import { RateLimitStore } from '../rate-limit/rate-limit.store.js';
import type { DeviceStore } from '../zero-trust/device/device.store.js';
import { RiskMemoryStore } from '../zero-trust/index.js';
import type { Type } from '@nestjs/common';

export type ProviderToken<T = unknown> = string | symbol | Type<T>;

export interface SecurityJwtOptions {
  issuer: string;
  jwksUri: string;
  audience?: string;
  /** Name of the tenant claim accepted after JWT verification. */
  tenantClaim?: string;
}

export interface SecuritySessionOptions {
  ttlMs: number;
}

export interface SecurityRateLimitOptions {
  enabled?: boolean;
  defaultLimit?: number;
  defaultWindowMs?: number;
  rateLimitStore?: RateLimitStore;
  imports?: any[];
}

export interface SecurityCookieOptions {
  domain?: string;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  accessTokenName?: string;
  refreshTokenName?: string;
  accessTokenMaxAgeMs?: number;
  refreshTokenMaxAgeMs?: number;
}

export interface RevocationStore {
  set(key: string, value: string, ttl?: number): Promise<void>;
  exists(key: string): Promise<boolean>;
}

export interface GeoIpOptions {
  provider?: 'ip-api' | 'ipinfo';
  ipinfoToken?: string;
}

export interface ZeroTrustOptions {
  device?: DeviceStore;
  deviceTrustTtlSeconds?: number;
  geoip?: GeoIpOptions;
  riskMemoryStore?: RiskMemoryStore;
  imports?: any[];
}

export interface HashOptions {
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
  pepper?: string;

  encryptionKey?: string;

  hmacResetToken?: string;
  hmacDeviceFingerprint?: string;
  hmacMagicLink?: string;
}

export interface SecurityModuleOptions {
  jwt: SecurityJwtOptions;
  jwe?: JweModuleOptions;
  session?: SecuritySessionOptions;
  cookie?: SecurityCookieOptions;
  hash?: HashOptions;
  zeroTrust?: ZeroTrustOptions;
  distributed?: {
    revocationStore?: RevocationStore;
    auditProducer?: any;
  };

  fingerprintSecret?: string;
  globalGuards?: boolean;

  rateLimit?: SecurityRateLimitOptions;

  /**
   * Enables canonical tenant verification for every request (wired into the
   * shared `ContextInterceptor` via the `CONTEXT_TENANT_VERIFIER` token).
   * Requires a Valkey-backed cache service and the tenant gRPC service.
   */
  tenantVerification?: TenantVerificationOptions;
}
