import { Injectable, Optional } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';

export interface JweKey {
  kid: string;
  material: Uint8Array;
}

@Injectable()
export class KeyringProvider {
  private readonly keys: JweKey[] = [];
  private readonly enabled: boolean;

  constructor(
    keys?: JweKey[],
    @Optional() private readonly logger?: OmnixysLogger,
  ) {
    if (!keys || keys.length === 0) {
      this.enabled = false;
      this.logger?.child(KeyringProvider.name).warn('JWE keyring is disabled', {
        reason: 'missing_keys',
      });
      return;
    }

    this.keys = keys;
    this.enabled = true;
  }

  private assertEnabled(): void {
    if (!this.enabled || this.keys.length === 0) {
      throw new Error('KeyringProvider is not configured (no keys)');
    }
  }

  getActive(): JweKey {
    this.assertEnabled();
    return this.keys[0];
  }

  getAll(): JweKey[] {
    this.assertEnabled();
    return this.keys;
  }
}
