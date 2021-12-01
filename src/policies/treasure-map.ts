import {
  Capsule,
  encrypt,
  PublicKey,
  Signature,
  Signer,
  VerifiedKeyFrag,
} from 'umbral-pre';

import { Alice } from '../characters/alice';
import { Bob } from '../characters/bob';
import { Ursula } from '../characters/porter';
import {
  ETH_ADDRESS_BYTE_LENGTH,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
} from '../crypto/constants';
import { toCanonicalAddress, toChecksumAddress } from '../crypto/utils';
import { MessageKit } from '../kits/message';
import { ChecksumAddress } from '../types';
import {
  decodeVariableLengthMessage,
  encodeVariableLengthMessage,
  fromHexString,
  split,
  zip,
} from '../utils';
import {
  Deserializer,
  Versioned,
  VersionedDeserializers,
  VersionedParser,
  VersionHandler,
  VersionTuple,
} from '../versioning';

import { HRAC } from './hrac';
import { AuthorizedKeyFrag, EncryptedKeyFrag } from './key-frag';

export type KFragDestinations = Record<ChecksumAddress, EncryptedKeyFrag>;

export class TreasureMap implements Versioned {
  private static readonly BRAND = 'TMap';
  private static readonly VERSION: VersionTuple = [1, 0];

  constructor(
    public readonly threshold: number,
    public readonly hrac: HRAC,
    public readonly policyEncryptingKey: PublicKey,
    public readonly publisherVerifyingKey: PublicKey,
    public readonly destinations: KFragDestinations
  ) {}

  public static async constructByPublisher(
    hrac: HRAC,
    publisher: Alice,
    ursulas: readonly Ursula[],
    verifiedKFrags: readonly VerifiedKeyFrag[],
    threshold: number,
    policyEncryptingKey: PublicKey
  ): Promise<TreasureMap> {
    if (threshold < 1 || threshold > 255) {
      throw Error('The threshold must be between 1 and 255.');
    }

    const nUrsulas = Object.keys(ursulas).length;
    if (nUrsulas < threshold) {
      throw Error(
        `The number of destinations (${nUrsulas}) must be equal or greater than the threshold (${threshold})`
      );
    }

    const destinations = TreasureMap.makeDestinations(
      ursulas,
      verifiedKFrags,
      hrac,
      publisher
    );
    return new TreasureMap(
      threshold,
      hrac,
      policyEncryptingKey,
      publisher.verifyingKey,
      destinations
    );
  }

  public static fromBytes(bytes: Uint8Array): TreasureMap {
    return VersionedParser.fromVersionedBytes(this.getVersionHandler(), bytes);
  }

  protected static getVersionHandler(): VersionHandler {
    const oldVersionDeserializers = (): VersionedDeserializers => {
      return {};
    };
    const currentVersionDeserializer: Deserializer = <T extends Versioned>(
      bytes: Uint8Array
    ): T => {
      const [thresholdBytes, remainder1] = split(bytes, 1);
      const [hracBytes, remainder2] = split(remainder1, HRAC.BYTE_LENGTH);
      const [policyEncryptingKeyBytes, remainder3] = split(
        remainder2,
        PUBLIC_KEY_LENGTH
      );
      const [publisherVerifyingKeyBytes, remainder4] = split(
        remainder3,
        PUBLIC_KEY_LENGTH
      );

      const threshold = thresholdBytes.reverse()[0];
      const hrac = new HRAC(hracBytes);
      const policyEncryptingKey = PublicKey.fromBytes(policyEncryptingKeyBytes);
      const publisherVerifyingKey = PublicKey.fromBytes(
        publisherVerifyingKeyBytes
      );
      const nodes = this.bytesToNodes(remainder4);
      return new TreasureMap(
        threshold,
        hrac,
        policyEncryptingKey,
        publisherVerifyingKey,
        nodes
      ) as unknown as T;
    };
    return {
      oldVersionDeserializers,
      currentVersionDeserializer,
      brand: this.BRAND,
      version: this.VERSION,
    };
  }

  private static makeDestinations(
    ursulas: readonly Ursula[],
    verifiedKFrags: readonly VerifiedKeyFrag[],
    hrac: HRAC,
    publisher: Alice
  ): KFragDestinations {
    const destinations: KFragDestinations = {};
    zip(ursulas, verifiedKFrags).forEach(([ursula, verifiedKFrag]) => {
      const kFragPayload = AuthorizedKeyFrag.constructByPublisher(
        publisher.signer,
        hrac,
        verifiedKFrag
      );
      const ursulaEncryptingKey = PublicKey.fromBytes(
        fromHexString(ursula.encryptingKey)
      );
      destinations[ursula.checksumAddress] = EncryptedKeyFrag.author(
        ursulaEncryptingKey,
        kFragPayload
      );
    });
    return destinations;
  }

  private static bytesToNodes(bytes: Uint8Array): KFragDestinations {
    const destinations: KFragDestinations = {};
    let bytesRemaining = decodeVariableLengthMessage(bytes)[0];
    while (bytesRemaining.length > 0) {
      const [addressBytes, remainder1] = split(
        bytesRemaining,
        ETH_ADDRESS_BYTE_LENGTH
      );
      const address = toChecksumAddress(addressBytes);
      const { encryptedKeyFrag, remainder } = EncryptedKeyFrag.take(remainder1);
      destinations[address] = encryptedKeyFrag;
      bytesRemaining = remainder;
    }
    return destinations;
  }

  public encrypt(
    publisher: Alice,
    recipientKey: PublicKey
  ): EncryptedTreasureMap {
    return EncryptedTreasureMap.constructByPublisher(
      this,
      publisher,
      recipientKey
    );
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(TreasureMap.BRAND, TreasureMap.VERSION);
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      // `threshold` must be big-endian
      ...Uint8Array.from([this.threshold]).reverse(),
      ...this.hrac.toBytes(),
      ...this.policyEncryptingKey.toBytes(),
      ...this.publisherVerifyingKey.toBytes(),
      ...TreasureMap.nodesToBytes(this.destinations),
    ]);
  }

  private static nodesToBytes(destinations: KFragDestinations): Uint8Array {
    const bytes = Object.entries(destinations)
      .map(
        ([ursulaAddress, encryptedKFrag]) =>
          new Uint8Array([
            ...toCanonicalAddress(ursulaAddress),
            ...encryptedKFrag.toBytes(),
          ])
      )
      .reduce((previous, next) => new Uint8Array([...previous, ...next]));
    return encodeVariableLengthMessage(bytes);
  }
}

export class AuthorizedTreasureMap implements Versioned {
  private static readonly BRAND = 'AMap';
  private static readonly VERSION: VersionTuple = [1, 0];

  constructor(
    private readonly signature: Signature,
    private readonly treasureMap: TreasureMap
  ) {}

  public static constructByPublisher(
    signer: Signer,
    recipientKey: PublicKey,
    treasureMap: TreasureMap
  ): AuthorizedTreasureMap {
    const payload = new Uint8Array([
      ...recipientKey.toBytes(),
      ...treasureMap.toBytes(),
    ]);
    const signature = signer.sign(payload);
    return new AuthorizedTreasureMap(signature, treasureMap);
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      AuthorizedTreasureMap.BRAND,
      AuthorizedTreasureMap.VERSION
    );
  }

  public verify(
    recipientKey: PublicKey,
    publisherVerifyingKey: PublicKey
  ): TreasureMap {
    const payload = new Uint8Array([
      ...recipientKey.toBytes(),
      ...this.treasureMap.toBytes(),
    ]);
    const isValid = this.signature.verify(publisherVerifyingKey, payload);
    if (!isValid) {
      throw new Error('Invalid publisher signature');
    }
    return this.treasureMap;
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.signature.toBytes(),
      ...this.treasureMap.toBytes(),
    ]);
  }

  protected static getVersionHandler(): VersionHandler {
    const oldVersionDeserializers = (): VersionedDeserializers => {
      return {};
    };
    const currentVersionDeserializer: Deserializer = <T extends Versioned>(
      bytes: Uint8Array
    ): T => {
      const [signature, treasureMap] = split(bytes, SIGNATURE_LENGTH);
      return new AuthorizedTreasureMap(
        Signature.fromBytes(signature),
        TreasureMap.fromBytes(treasureMap)
      ) as unknown as T;
    };
    return {
      oldVersionDeserializers,
      currentVersionDeserializer,
      brand: AuthorizedTreasureMap.BRAND,
      version: AuthorizedTreasureMap.VERSION,
    };
  }

  public static fromBytes(bytes: Uint8Array): AuthorizedTreasureMap {
    return VersionedParser.fromVersionedBytes(
      AuthorizedTreasureMap.getVersionHandler(),
      bytes
    );
  }
}

export class EncryptedTreasureMap implements Versioned {
  private static readonly BRAND = 'EMap';
  private static readonly VERSION: VersionTuple = [1, 0];

  constructor(
    public readonly capsule: Capsule,
    public readonly ciphertext: Uint8Array
  ) {}

  public static constructByPublisher(
    treasureMap: TreasureMap,
    publisher: Alice,
    recipientKey: PublicKey
  ): EncryptedTreasureMap {
    const authorizedTreasureMap = AuthorizedTreasureMap.constructByPublisher(
      publisher.signer,
      recipientKey,
      treasureMap
    );
    const { capsule, ciphertext } = encrypt(
      recipientKey,
      authorizedTreasureMap.toBytes()
    );
    return new EncryptedTreasureMap(capsule, ciphertext);
  }

  public static sign(
    blockchainSigner: Signer,
    publicSignature: Signature,
    hrac: HRAC,
    encryptedTreasureMap: MessageKit
  ): Signature {
    const payload = new Uint8Array([
      ...publicSignature.toBytes(),
      ...hrac.toBytes(),
      ...encryptedTreasureMap.ciphertext,
    ]);
    return blockchainSigner.sign(payload);
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      EncryptedTreasureMap.BRAND,
      EncryptedTreasureMap.VERSION
    );
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.capsule.toBytes(),
      ...encodeVariableLengthMessage(this.ciphertext),
    ]);
  }

  public decrypt(bob: Bob): AuthorizedTreasureMap {
    const encrypted = new MessageKit(this.capsule, this.ciphertext);
    const bytes = bob.decrypt(encrypted);
    return AuthorizedTreasureMap.fromBytes(bytes);
  }
}
