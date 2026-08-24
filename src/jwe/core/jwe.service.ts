import { KeyringProvider } from './keyring.provider.js';
import { Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import * as jose from 'jose';

@Injectable()
export class JweService {
  private readonly log;

  constructor(
    private readonly keyring: KeyringProvider,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
  }

  async encrypt(payload: unknown): Promise<string> {
    const active = this.keyring.getActive();

    return new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({
        alg: 'dir',
        enc: 'A256GCM',
        kid: active.kid,
      })
      .encrypt(active.material);
  }

  async decrypt<T>(token: string): Promise<T> {
    const keys = this.keyring.getAll();

    for (const key of keys) {
      try {
        const { plaintext } = await jose.compactDecrypt(token, key.material);
        return JSON.parse(new TextDecoder().decode(plaintext)) as T;
      } catch {
        // try next key
      }
    }

    this.log?.error('JWE decryption failed with all keyring keys', {
      reason: 'decryption_failed',
    });
    throw new Error('Unable to decrypt token with any key');
  }
}
