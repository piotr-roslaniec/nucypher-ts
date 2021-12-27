import { VerifiedCapsuleFrag } from 'umbral-pre';

import { toCanonicalAddress } from '../crypto/utils';
import { ChecksumAddress } from '../types';
import { encodeVariableLengthMessage } from '../utils';
import { Versioned, VersionedParser, VersionTuple } from '../versioning';

export class RetrievalResult {
  public readonly cFrags: Record<ChecksumAddress, VerifiedCapsuleFrag>;

  constructor(cFrags?: Record<ChecksumAddress, VerifiedCapsuleFrag>) {
    this.cFrags = cFrags ? cFrags : {};
  }

  public static empty(): RetrievalResult {
    return new RetrievalResult();
  }

  public get addresses(): readonly ChecksumAddress[] {
    return Object.keys(this.cFrags);
  }

  public withResult(result: RetrievalResult): RetrievalResult {
    const cFrags = Object.assign(this.cFrags, result.cFrags);
    return new RetrievalResult(cFrags);
  }
}

export class RetrievalKit implements Versioned {
  private static readonly BRAND = 'RKit';
  private static readonly VERSION: VersionTuple = [1, 0];

  constructor(
    public readonly capsule: VerifiedCapsuleFrag,
    public readonly queriedAddresses: readonly ChecksumAddress[]
  ) {}

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      RetrievalKit.BRAND,
      RetrievalKit.VERSION
    );
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.capsule.toBytes(),
      ...encodeVariableLengthMessage(
        this.queriedAddresses
          .map(toCanonicalAddress)
          .reduce(
            (previous, next) => new Uint8Array([...previous, ...next]),
            new Uint8Array()
          )
      ),
    ]);
  }
}
