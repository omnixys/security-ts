/**
 * @license GPL-3.0-or-later
 */

import { HashOptions } from '../types/security.types.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { createHmac, timingSafeEqual } from 'crypto';

type HmacPurpose = 'resetToken' | 'deviceFingerprint' | 'magicLink';

@Injectable()
export class HmacService {
  private readonly keys: Partial<Record<HmacPurpose, Buffer>> = {};
  private readonly log;

  constructor(
    @Optional()
    @Inject('HASH_OPTIONS')
    readonly hashOption: HashOptions = {},
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    this.log = this.logger?.log(this.constructor.name);
    this.initKey('resetToken', hashOption.hmacResetToken, 'RESET_TOKEN_HMAC_SECRET');
    this.initKey(
      'deviceFingerprint',
      hashOption.hmacDeviceFingerprint,
      'DEVICE_FINGERPRINT_HMAC_SECRET',
    );
    this.initKey('magicLink', hashOption.hmacMagicLink, 'MAGIC_LINK_HMAC_SECRET');
  }

  private initKey(purpose: HmacPurpose, raw: string | undefined, name: string): void {
    if (!raw || raw.length < 32) {
      this.logger?.child(HmacService.name).warn('HMAC purpose is disabled', {
        configurationName: name,
        purpose,
      });
      return;
    }

    this.keys[purpose] = Buffer.from(raw, 'utf8');
  }

  private getKey(purpose: HmacPurpose): Buffer {
    const key = this.keys[purpose];

    if (!key) {
      this.log?.error('HMAC key requested but not configured', { purpose });
      throw new Error(`HMAC key for "${purpose}" is not configured`);
    }

    return key;
  }

  /**
   * Deterministic HMAC-SHA256 hash (hex).
   */
  hash(value: string, purpose: HmacPurpose): string {
    const key = this.getKey(purpose);

    return createHmac('sha256', key).update(value, 'utf8').digest('hex');
  }

  /**
   * Timing-safe comparison for hex digests.
   */
  equals(aHex: string, bHex: string): boolean {
    const a = Buffer.from(aHex, 'hex');
    const b = Buffer.from(bHex, 'hex');

    if (a.length !== b.length) {
      return false;
    }

    return timingSafeEqual(a, b);
  }
}
