import { ClientGrpc } from '@nestjs/microservices';
import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ContextAccessor } from '@omnixys/context-ts';
import type { TenantVerifier } from '@omnixys/context-ts';
import type {
  TenantServiceClient,
  ValidateMembershipResponse,
} from '@omnixys/grpc-ts';
import { ValkeyService } from '@omnixys/cache-ts';
import * as grpc from '@grpc/grpc-js';

import { TENANT_GRPC_CLIENT, TENANT_VERIFICATION_OPTIONS } from '../security.constants.js';
import {
  TenantContextUnverifiedException,
  TenantDisabledException,
  TenantMembershipInactiveException,
  TenantMembershipNotFoundException,
  TenantNotFoundException,
  TenantServiceUnavailableException,
} from '../errors/tenant.exception.js';

export interface TenantVerificationOptions {
  /** gRPC endpoint of the tenant service, e.g. `localhost:50052`. */
  readonly url: string;
  /** Caller bearer token authorized to read from the tenant service. */
  readonly callerToken: string;
  /** Enable the positive membership cache (Valkey). Defaults to true. */
  readonly cache?: boolean;
}

interface ValidateMembershipCall {
  (
    request: { tenantId: string; userId?: string },
    metadata?: grpc.Metadata,
  ): Promise<ValidateMembershipResponse>;
}

const CACHE_TTL_SECONDS = 45;
const CACHE_PREFIX = 'tenant:membership';

@Injectable()
export class TenantVerifierService implements TenantVerifier {
  private readonly logger = new Logger(TenantVerifierService.name);

  constructor(
    @Inject(TENANT_VERIFICATION_OPTIONS)
    private readonly options: TenantVerificationOptions,
    @Inject(TENANT_GRPC_CLIENT) private readonly grpc: ClientGrpc,
    @Optional()
    @Inject(ValkeyService)
    private readonly cache?: ValkeyService,
  ) {}

  async verify(input: { userId?: string; tenantId: string }): Promise<void> {
    const { userId, tenantId } = input;

    if (userId) {
      const cacheKey = this.cacheKey(userId, tenantId);
      if (await this.cachedHit(cacheKey)) {
        return;
      }
      const result = await this.callValidateMembership(tenantId, userId);
      this.assertMembershipAllowed(result, tenantId, userId);
      await this.cachePositive(cacheKey);
      return;
    }

    const result = await this.callValidateMembership(tenantId);
    this.assertTenantAllowed(result, tenantId);
  }

  private async cachedHit(cacheKey: string): Promise<boolean> {
    if (!this.cache || this.options.cache === false) {
      return false;
    }

    try {
      const hit = await this.cache.rawGet(cacheKey);
      return hit !== null;
    } catch (error) {
      this.logger.warn(
        `Membership cache read failed, falling back to tenant service: ${
          (error as Error).message
        }`,
      );
      return false;
    }
  }

  private async cachePositive(cacheKey: string): Promise<void> {
    if (!this.cache || this.options.cache === false) {
      return;
    }

    try {
      await this.cache.rawSet(cacheKey, '1', CACHE_TTL_SECONDS);
    } catch (error) {
      this.logger.warn(
        `Membership cache write failed: ${(error as Error).message}`,
      );
    }
  }

  private cacheKey(userId: string, tenantId: string): string {
    return `${CACHE_PREFIX}:${userId}:${tenantId}`;
  }

  private async callValidateMembership(
    tenantId: string,
    userId?: string,
  ): Promise<ValidateMembershipResponse> {
    const client = this.grpc.getService<TenantServiceClient>('TenantService');
    const metadata = new grpc.Metadata();
    metadata.set('authorization', `Bearer ${this.options.callerToken}`);

    try {
      const validateMembership = client.validateMembership as unknown as ValidateMembershipCall;
      return await validateMembership(
        { tenantId, ...(userId ? { userId } : {}) },
        metadata,
      );
    } catch (error) {
      const code = this.resolveGrpcCode(error);
      if (code === grpc.status.INVALID_ARGUMENT) {
        throw new TenantContextUnverifiedException(tenantId, {
          reason: 'tenant_verification_rejected',
          grpcCode: code,
          ...this.scopeMetadata(),
        });
      }

      throw new TenantServiceUnavailableException(tenantId, {
        reason: 'tenant_service_unavailable',
        grpcCode: code ?? undefined,
        ...this.scopeMetadata(),
      });
    }
  }

  private assertMembershipAllowed(
    result: ValidateMembershipResponse,
    tenantId: string,
    userId: string,
  ): void {
    const metadata = this.scopeMetadata();

    if (!result.tenantExists) {
      throw new TenantNotFoundException(tenantId, metadata);
    }
    if (!result.tenantActive) {
      throw new TenantDisabledException(tenantId, {
        ...metadata,
        reason: result.reason || undefined,
      });
    }
    if (!result.membershipExists) {
      throw new TenantMembershipNotFoundException(tenantId, userId, metadata);
    }
    if (!result.membershipActive) {
      throw new TenantMembershipInactiveException(tenantId, userId, {
        ...metadata,
        reason: result.reason || undefined,
      });
    }
  }

  private assertTenantAllowed(
    result: ValidateMembershipResponse,
    tenantId: string,
  ): void {
    const metadata = this.scopeMetadata();

    if (!result.tenantExists) {
      throw new TenantNotFoundException(tenantId, metadata);
    }
    if (!result.tenantActive) {
      throw new TenantDisabledException(tenantId, {
        ...metadata,
        reason: result.reason || undefined,
      });
    }
  }

  private resolveGrpcCode(error: unknown): number | undefined {
    const candidate =
      (error as { code?: number | string }).code ??
      (error as { error?: { code?: number | string } }).error?.code;

    return typeof candidate === 'number' ? candidate : undefined;
  }

  private scopeMetadata(): Record<string, string> {
    const context = ContextAccessor.get();
    return {
      requestId: context?.requestId ?? 'unscoped',
      correlationId: context?.correlationId ?? context?.requestId ?? 'unscoped',
      traceId: context?.trace?.traceId ?? 'unscoped',
    };
  }
}
