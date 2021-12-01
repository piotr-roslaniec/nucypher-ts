import { Signature, Signer } from 'umbral-pre';

import { toCanonicalAddress } from '../crypto/utils';
import { EncryptedKeyFrag } from '../policies/key-frag';
import { TreasureMap } from '../policies/treasure-map';
import { ChecksumAddress } from '../types';
import { toBytes } from '../utils';
import { Versioned, VersionedParser, VersionTuple } from '../versioning';

export class RevocationKit {
  public readonly revocations: Record<ChecksumAddress, RevocationOrder>;

  constructor(treasureMap: TreasureMap, signer: Signer) {
    this.revocations = {};
    Object.entries(treasureMap.destinations).forEach(
      ([nodeId, encryptedKFrag]) => {
        this.revocations[nodeId] = new RevocationOrder(
          nodeId,
          encryptedKFrag,
          signer
        );
      }
    );
  }
}

class RevocationOrder implements Versioned {
  private static readonly BRAND = 'Revo';
  private static readonly VERSION: VersionTuple = [1, 0];
  private readonly PREFIX: Uint8Array = toBytes('REVOKE-');
  private readonly signature?: Signature;

  constructor(
    private readonly ursulaAddress: ChecksumAddress,
    private readonly encryptedKFrag: EncryptedKeyFrag,
    signer?: Signer,
    signature?: Signature
  ) {
    if (!!signature && !!signature) {
      throw Error('Either pass a signer or signature - not both');
    } else if (signer) {
      this.signature = signer.sign(this.payload);
    } else if (signature) {
      this.signature = signature;
    }
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      RevocationOrder.BRAND,
      RevocationOrder.VERSION
    );
  }

  public get payload(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.PREFIX,
      ...toCanonicalAddress(this.ursulaAddress),
      ...this.encryptedKFrag.toBytes(),
    ]);
  }
}
