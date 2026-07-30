import type { RevocationStore } from '../types/security.types.js';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';

@Injectable()
export class TokenRevocationService {
  constructor(
    @Inject('REVOCATION_STORE')
    private readonly store: RevocationStore,
    @Optional() private readonly logger?: OmnixysLogger,
  ) {}

  async revoke(jti: string, ttlSec: number): Promise<void> {
    await this.store.set(`revoked:${jti}`, '1', ttlSec);
    this.logger?.child(TokenRevocationService.name).info('Token revoked', {
      tokenId: jti,
      ttlSec,
    });
  }

  async isRevoked(jti: string): Promise<boolean> {
    return this.store.exists(`revoked:${jti}`);
  }
}
