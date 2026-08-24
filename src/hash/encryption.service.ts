import { HashOptions } from '../types/security.types.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

@Injectable()
export class EncryptionService {
  private readonly key?: Buffer;
  private readonly enabled: boolean;
  private readonly log;

  constructor(
    @Optional()
    @Inject('HASH_OPTIONS')
    readonly options: HashOptions = {},
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
    const keyTmp = options?.encryptionKey;

    if (!keyTmp) {
      this.enabled = false;
      this.logger
        ?.child(EncryptionService.name)
        .warn('Encryption service is disabled', { reason: 'missing_key' });
      return;
    }

    const key = Buffer.from(keyTmp, 'hex');

    if (key.length !== 32) {
      this.log?.error('Invalid encryption key length', {
        expectedBytes: 32,
        actualBytes: key.length,
      });
      throw new Error(`Invalid encryption key length: expected 32 bytes, got ${key.length}`);
    }

    this.key = key;
    this.enabled = true;
  }

  private getKey(): Buffer {
    if (!this.enabled || !this.key) {
      this.log?.error('Encryption key requested but service is not configured', {
        reason: 'missing_key',
      });
      throw new Error('EncryptionService is not configured (missing key)');
    }
    return this.key;
  }

  encrypt(plain: string, url: boolean = false): string {
    const key = this.getKey();

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, tag, encrypted]).toString(url ? 'base64url' : 'base64');
  }

  decrypt(payload: string, url: boolean = false): string {
    const key = this.getKey();

    try {
      if (!payload || typeof payload !== 'string') {
        throw new Error('Payload must be a base64 string');
      }

      const buffer = Buffer.from(payload, url ? 'base64url' : 'base64');

      if (buffer.length < 28) {
        throw new Error('Invalid encrypted payload');
      }

      if (buffer.length < 12 + 16) {
        throw new Error('Invalid encrypted payload');
      }

      const iv = buffer.subarray(0, 12);
      const tag = buffer.subarray(12, 28);
      const encrypted = buffer.subarray(28);

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

      return decrypted.toString('utf8');
    } catch {
      this.log?.error('Decryption rejected', {
        reason: 'invalid_payload_or_key',
      });
      throw new Error('Decryption failed: invalid payload or key');
    }
  }
}
