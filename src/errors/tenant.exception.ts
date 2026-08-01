import {
  ForbiddenException,
  HttpStatus,
  InternalServerErrorException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ContextAccessor } from '@omnixys/context-ts';
import { ErrorCode } from '@omnixys/contracts-ts';

export interface TenantErrorContext {
  readonly requestId: string;
  readonly correlationId: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
}

export type TenantErrorMetadata = Readonly<Record<string, unknown>>;

export interface TenantErrorDetails extends TenantErrorContext {
  readonly code: string;
  readonly message: string;
  readonly httpStatus: number;
  readonly metadata: TenantErrorMetadata;
}

function tenantErrorDetails(
  code: string,
  message: string,
  httpStatus: HttpStatus,
  metadata: TenantErrorMetadata = {},
): TenantErrorDetails {
  const context = ContextAccessor.get();

  return {
    code,
    message,
    httpStatus,
    requestId: context?.requestId ?? 'unscoped',
    correlationId: context?.correlationId ?? context?.requestId ?? 'unscoped',
    traceId: context?.trace?.traceId,
    actorId: context?.principal?.actorId,
    tenantId: context?.tenant?.tenantId ?? context?.principal?.tenantId,
    metadata,
  };
}

function attach(
  target: {
    code: string;
    httpStatus: number;
    requestId?: string;
    correlationId?: string;
    traceId?: string;
    actorId?: string;
    tenantId?: string;
    metadata: TenantErrorMetadata;
  },
  details: TenantErrorDetails,
): void {
  target.code = details.code;
  target.httpStatus = details.httpStatus;
  target.requestId = details.requestId;
  target.correlationId = details.correlationId;
  target.traceId = details.traceId;
  target.actorId = details.actorId;
  target.tenantId = details.tenantId;
  target.metadata = details.metadata;
}

export class TenantNotFoundException extends NotFoundException {
  readonly code = ErrorCode.TENANT_NOT_FOUND;
  readonly httpStatus = HttpStatus.NOT_FOUND;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_NOT_FOUND,
      `Tenant does not exist: ${tenantId}`,
      HttpStatus.NOT_FOUND,
      { ...metadata, tenantId },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantDisabledException extends ForbiddenException {
  readonly code = ErrorCode.TENANT_DISABLED;
  readonly httpStatus = HttpStatus.FORBIDDEN;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_DISABLED,
      `Tenant is not active: ${tenantId}`,
      HttpStatus.FORBIDDEN,
      { ...metadata, tenantId },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantMembershipNotFoundException extends ForbiddenException {
  readonly code = ErrorCode.TENANT_MEMBERSHIP_NOT_FOUND;
  readonly httpStatus = HttpStatus.FORBIDDEN;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string,
    userId: string,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_MEMBERSHIP_NOT_FOUND,
      `No membership exists for user in tenant`,
      HttpStatus.FORBIDDEN,
      { ...metadata, tenantId, userId },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantMembershipInactiveException extends ForbiddenException {
  readonly code = ErrorCode.TENANT_MEMBERSHIP_INACTIVE;
  readonly httpStatus = HttpStatus.FORBIDDEN;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string,
    userId: string,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_MEMBERSHIP_INACTIVE,
      `Membership is not active for user in tenant`,
      HttpStatus.FORBIDDEN,
      { ...metadata, tenantId, userId },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantMembershipDeniedException extends ForbiddenException {
  readonly code = ErrorCode.TENANT_MEMBERSHIP_DENIED;
  readonly httpStatus = HttpStatus.FORBIDDEN;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string,
    userId: string,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_MEMBERSHIP_DENIED,
      `User has no active membership in tenant`,
      HttpStatus.FORBIDDEN,
      { ...metadata, tenantId, userId },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantServiceUnavailableException extends ServiceUnavailableException {
  readonly code = ErrorCode.TENANT_SERVICE_UNAVAILABLE;
  readonly httpStatus = HttpStatus.SERVICE_UNAVAILABLE;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string | undefined,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_SERVICE_UNAVAILABLE,
      'The tenant service is temporarily unavailable',
      HttpStatus.SERVICE_UNAVAILABLE,
      { ...metadata, ...(tenantId ? { tenantId } : {}) },
    );
    super(details);
    attach(this, details);
  }
}

export class TenantContextUnverifiedException extends InternalServerErrorException {
  readonly code = ErrorCode.TENANT_CONTEXT_UNVERIFIED;
  readonly httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: TenantErrorMetadata;

  constructor(
    tenantId: string | undefined,
    metadata: TenantErrorMetadata = {},
  ) {
    const details = tenantErrorDetails(
      ErrorCode.TENANT_CONTEXT_UNVERIFIED,
      'Executed with an unverified tenant context',
      HttpStatus.INTERNAL_SERVER_ERROR,
      { ...metadata, ...(tenantId ? { tenantId } : {}) },
    );
    super(details);
    attach(this, details);
  }
}
