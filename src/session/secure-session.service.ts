import { SessionExpiredException } from '../errors/security.exception.js';
import { JweService } from '../jwe/core/jwe.service.js';
import { SECURITY_OPTIONS } from '../security.constants.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { randomUUID } from 'node:crypto';

export interface SessionMetadata {
  readonly sessionId: string;
  readonly issuedAtEpochMs: number;
  readonly expiresAtEpochMs: number;
  readonly authenticatedAtEpochMs: number;
  readonly authStrength?: string;
}

export interface SessionIssueOptions {
  readonly sessionId?: string;
  readonly authenticatedAtEpochMs?: number;
  readonly authStrength?: string;
}

@Injectable()
export class SecureSessionService {
  private readonly log;

  constructor(
    private readonly jwe: JweService,
    @Inject(SECURITY_OPTIONS) private readonly options: any,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name, 'package:@omnixys/security-ts');
  }

  async issue<T extends Record<string, unknown>>(
    payload: T,
    metadata: SessionIssueOptions = {},
  ): Promise<string> {
    const ttl = this.options.session?.ttlMs ?? 1000 * 60 * 60;
    const issuedAtEpochMs = Date.now();

    return this.jwe.encrypt({
      ...payload,
      sid: metadata.sessionId ?? randomUUID(),
      iat: issuedAtEpochMs,
      exp: issuedAtEpochMs + ttl,
      authenticatedAtEpochMs: metadata.authenticatedAtEpochMs ?? issuedAtEpochMs,
      authStrength: metadata.authStrength,
    });
  }

  async read<T>(token: string): Promise<T> {
    const data = await this.jwe.decrypt<any>(token);

    if (data.exp && Date.now() > data.exp) {
      this.log?.error('Session read rejected', {
        reason: 'expired',
      });
      throw new SessionExpiredException();
    }

    return data;
  }

  async metadata(token: string): Promise<SessionMetadata> {
    const data = await this.read<{
      sid?: unknown;
      iat?: unknown;
      exp?: unknown;
      authenticatedAtEpochMs?: unknown;
      authStrength?: unknown;
    }>(token);

    if (
      typeof data.sid !== 'string' ||
      typeof data.iat !== 'number' ||
      typeof data.exp !== 'number'
    ) {
      this.log?.error('Session metadata is invalid', {
        reason: 'invalid_session_metadata',
      });
      throw new InvalidSessionMetadataException();
    }

    return {
      sessionId: data.sid,
      issuedAtEpochMs: data.iat,
      expiresAtEpochMs: data.exp,
      authenticatedAtEpochMs:
        typeof data.authenticatedAtEpochMs === 'number' ? data.authenticatedAtEpochMs : data.iat,
      authStrength: typeof data.authStrength === 'string' ? data.authStrength : undefined,
    };
  }
}

class InvalidSessionMetadataException extends SessionExpiredException {
  constructor() {
    super('Session metadata is invalid', { reason: 'invalid_session_metadata' });
  }
}
