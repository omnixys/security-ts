import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { ContextAccessor } from '@omnixys/context-ts';
import { ErrorCode } from '@omnixys/contracts-ts';

export interface SecurityErrorContext {
  readonly requestId: string;
  readonly correlationId: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
}

export type SecurityErrorMetadata = Readonly<Record<string, unknown>>;

/** Common machine-readable shape used by security and transport error mappers. */
export interface SecurityErrorDetails extends SecurityErrorContext {
  readonly code: string;
  readonly message: string;
  readonly metadata: SecurityErrorMetadata;
}

export class InvalidCredentialsException extends UnauthorizedException {
  readonly code = ErrorCode.INVALID_CREDENTIALS;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Invalid credentials',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(
      ErrorCode.INVALID_CREDENTIALS,
      message,
      metadata,
    );
    super(details);
    Object.assign(this, details);
  }
}

export class RefreshTokenExpiredException extends UnauthorizedException {
  readonly code = ErrorCode.REFRESH_TOKEN_EXPIRED;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Refresh token has expired',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(
      ErrorCode.REFRESH_TOKEN_EXPIRED,
      message,
      metadata,
    );
    super(details);
    Object.assign(this, details);
  }
}

export class UnauthorizedTenantException extends ForbiddenException {
  readonly code = ErrorCode.UNAUTHORIZED_TENANT;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Tenant access is not authorized',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(
      ErrorCode.UNAUTHORIZED_TENANT,
      message,
      metadata,
    );
    super(details);
    Object.assign(this, details);
  }
}

export class SessionExpiredException extends UnauthorizedException {
  readonly code = ErrorCode.SESSION_EXPIRED;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Session expired',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(ErrorCode.SESSION_EXPIRED, message, metadata);
    super(details);
    Object.assign(this, details);
  }
}

export interface RateLimitExceededOptions {
  readonly retryAfterSeconds?: number;
  readonly message?: string;
}

export class AuthenticationRequiredException extends UnauthorizedException {
  readonly code = ErrorCode.UNAUTHORIZED;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Authentication is required',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(ErrorCode.UNAUTHORIZED, message, metadata);
    super(details);
    Object.assign(this, details);
  }
}

export class ForbiddenOperationException extends ForbiddenException {
  readonly code = ErrorCode.FORBIDDEN;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;

  constructor(
    message = 'Operation is not authorized',
    metadata: SecurityErrorMetadata = {},
  ) {
    const details = errorDetails(ErrorCode.FORBIDDEN, message, metadata);
    super(details);
    Object.assign(this, details);
  }
}

export class RateLimitExceededException extends HttpException {
  readonly code = ErrorCode.RATE_LIMIT_EXCEEDED;
  readonly requestId!: string;
  readonly correlationId!: string;
  readonly traceId?: string;
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly metadata!: SecurityErrorMetadata;
  readonly retryAfterSeconds: number;

  constructor({
    retryAfterSeconds = 3600,
    message = 'Too many requests',
  }: RateLimitExceededOptions = {}) {
    const details = errorDetails(ErrorCode.RATE_LIMIT_EXCEEDED, message, {
      retryAfterSeconds,
    });
    super(
      {
        ...details,
        retryAfter: retryAfterSeconds,
      },
      HttpStatus.TOO_MANY_REQUESTS,
    );
    this.retryAfterSeconds = retryAfterSeconds;
    Object.assign(this, details);
  }
}

export function getSecurityErrorContext(): SecurityErrorContext {
  const context = ContextAccessor.get();

  return {
    requestId: context?.requestId ?? 'unscoped',
    correlationId: context?.correlationId ?? context?.requestId ?? 'unscoped',
    traceId: context?.trace?.traceId,
    actorId: context?.principal?.actorId,
    tenantId: context?.tenant?.tenantId ?? context?.principal?.tenantId,
  };
}

export function errorDetails(
  code: string,
  message: string,
  metadata: SecurityErrorMetadata = {},
): SecurityErrorDetails {
  return {
    code,
    message,
    ...getSecurityErrorContext(),
    metadata,
  };
}
