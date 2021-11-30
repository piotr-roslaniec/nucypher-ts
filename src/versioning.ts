import { fromBytes, numberToBytes, split, toBytes, toNumber } from './utils';

export type Deserializer = <T extends Versioned>(bytes: Uint8Array) => T;

export type VersionedDeserializers = Record<
  number,
  Record<number, Deserializer>
>;

export type VersionTuple = readonly [number, number];

export type VersionHandler = {
  readonly brand: string;
  readonly version: VersionTuple;
  readonly currentVersionDeserializer: Deserializer;

  oldVersionDeserializers(): VersionedDeserializers;
};

export abstract class Versioned {
  public static readonly BRAND: string;

  public static readonly VERSION: VersionTuple;

  private static readonly getVersionHandler: VersionHandler;
}

export class VersionedParser {
  private static readonly VERSION_PART_LENGTH_BYTES = 2;
  private static readonly BRAND_LENGTH = 4;
  private static readonly HEADER_LENGTH =
    2 * VersionedParser.VERSION_PART_LENGTH_BYTES +
    VersionedParser.BRAND_LENGTH;

  public static encodeHeader(
    brand: string,
    [major, minor]: VersionTuple
  ): Uint8Array {
    const majorBytes = numberToBytes(
      major,
      VersionedParser.VERSION_PART_LENGTH_BYTES
    );
    const minorBytes = numberToBytes(
      minor,
      VersionedParser.VERSION_PART_LENGTH_BYTES
    );
    return new Uint8Array([...toBytes(brand), ...majorBytes, ...minorBytes]);
  }

  public static fromVersionedBytes<T extends Versioned>(
    handler: VersionHandler,
    bytes: Uint8Array
  ): T {
    const { brand, version } = handler;
    const { parsedVersion, payload } = this.parseHeader(brand, bytes);
    const selectedVersion = this.resolveVersion(version, parsedVersion);
    const deserializer = this.getDeserializer(handler, selectedVersion);
    return deserializer(payload);
  }

  private static parseHeader(
    brand: string,
    bytes: Uint8Array
  ): { parsedBrand: string; parsedVersion: VersionTuple; payload: Uint8Array } {
    if (bytes.length < VersionedParser.HEADER_LENGTH) {
      throw new Error('Invalid header length');
    }
    const [parsedBrand, remainder] = this.parseBrand(brand, bytes);
    if (brand !== parsedBrand) {
      throw new Error(
        `Parsed brand doesn't match. Expected ${brand}, received ${parsedBrand}`
      );
    }
    const [parsedVersion, payload] = this.parseVersion(remainder);
    return { parsedBrand, parsedVersion, payload };
  }

  private static parseBrand(
    brand: string,
    bytes: Uint8Array
  ): readonly [string, Uint8Array] {
    const [brandBytes, remainder] = split(bytes, VersionedParser.BRAND_LENGTH);
    const actualBrand = fromBytes(brandBytes);
    if (actualBrand !== brand) {
      throw new Error(`Invalid brand. Expected ${brand}, got ${actualBrand}`);
    }
    return [actualBrand, remainder];
  }

  private static parseVersion(
    bytes: Uint8Array
  ): readonly [VersionTuple, Uint8Array] {
    const [majorBytes, remainder1] = split(
      bytes,
      VersionedParser.VERSION_PART_LENGTH_BYTES
    );
    const [minorBytes, remainder2] = split(
      remainder1,
      VersionedParser.VERSION_PART_LENGTH_BYTES
    );
    const major = toNumber(majorBytes, false); // Is big-endian
    const minor = toNumber(minorBytes, false); // Is big-endian
    return [[major, minor], remainder2];
  }

  private static resolveVersion(
    version: VersionTuple,
    actualVersion: VersionTuple
  ): VersionTuple {
    const [latestMajor, latestMinor] = version;
    const [major, minor] = actualVersion;
    if (major !== latestMajor) {
      throw new Error(
        `Incompatible versions. Compatible version is ${latestMajor}.x, got ${major}.${minor}`
      );
    }
    // Enforce minor version compatibility.
    // Pass future minor versions to the latest minor handler.
    if (minor >= latestMinor) {
      return actualVersion;
    }
    return [major, minor];
  }

  private static getDeserializer(
    self: VersionHandler,
    version: VersionTuple
  ): Deserializer {
    const [major, minor] = version;
    const maybeOldMajor = self.oldVersionDeserializers()[major];
    const maybeOldMinor = maybeOldMajor ? maybeOldMajor[minor] : undefined;
    if (maybeOldMinor) {
      return maybeOldMinor;
    }
    return self.currentVersionDeserializer;
  }
}
