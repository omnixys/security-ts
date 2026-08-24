import { Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class KeyProvider {
  private readonly log;

  constructor(
    private readonly raw: string,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
  }

  getKey(): Uint8Array {
    if (!this.raw) {
      this.log?.error('JWE key requested but missing', {
        reason: 'missing_key',
      });
      throw new Error('JWE key missing');
    }

    // base64 first
    const buf = Buffer.from(this.raw, 'base64');

    if (buf.length === 32) {
      return buf;
    }

    // fallback UTF-8 BUT STRICT
    const utf8 = new TextEncoder().encode(this.raw);

    if (utf8.length !== 32) {
      this.log?.error('Invalid JWE key length', {
        actualBytes: utf8.length,
        requiredBytes: 32,
      });
      throw new Error(
        `Invalid JWE key length: ${utf8.length} bytes (required: 32 bytes)`,
      );
    }

    return utf8;
  }
}
