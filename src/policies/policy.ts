import { PublicKey, VerifiedKeyFrag } from 'umbral-pre';

import { PolicyManagerAgent } from '../agents/policy-manager';
import { Alice } from '../characters/alice';
import { RemoteBob } from '../characters/bob';
import { Ursula } from '../characters/porter';
import { RevocationKit } from '../kits/revocation';
import { ChecksumAddress } from '../types';

import { HRAC } from './hrac';
import { EncryptedTreasureMap, TreasureMap } from './treasure-map';

export type EnactedPolicy = {
  readonly id: HRAC;
  readonly label: string;
  readonly policyKey: PublicKey;
  readonly encryptedTreasureMap: EncryptedTreasureMap;
  readonly revocationKit: RevocationKit;
  readonly aliceVerifyingKey: Uint8Array;
  readonly ursulas: readonly Ursula[];
};

export type BlockchainPolicyParameters = {
  /** `RemoteBob` which represents the receiver of the encrypted messages. **/
  readonly bob: RemoteBob;
  /** Policy label **/
  readonly label: string;
  /** Policy threshold. "N" in the "N" of "N". **/
  readonly threshold: number;
  /** Policy shares. "M" in the "N" of "N". **/
  readonly shares: number;
  /** Policy expiration date. If left blank, will be calculated from `paymentPeriods`. **/
  expiration?: Date;
  /** Number of payment periods that the policy will be valid for. If left blank, will be calculated from `expiration`. **/
  paymentPeriods?: number;
  /** Policy value. Used to compensate Ursulas. If left blank, will be calculated from `rate`. **/
  value?: number;
  /** Fee rate to compensate Ursulas. If left blank, the global minimal rate will be fetched from staking contract instead. **/
  rate?: number;
};

export type ValidatedPolicyParameters = Omit<
  BlockchainPolicyParameters,
  'expiration' | 'paymentPeriods' | 'value' | 'rate'
> & {
  expiration: Date;
  paymentPeriods: number;
  value: number;
  rate: number;
};

export class BlockchainPolicy {
  public readonly hrac: HRAC;

  constructor(
    private readonly publisher: Alice,
    private readonly label: string,
    private readonly expiration: Date,
    private readonly bob: RemoteBob,
    private readonly verifiedKFrags: readonly VerifiedKeyFrag[],
    private readonly delegatingKey: PublicKey,
    private readonly threshold: number,
    private readonly shares: number,
    private readonly value: number
  ) {
    this.hrac = HRAC.derive(
      this.publisher.verifyingKey.toBytes(),
      this.bob.verifyingKey.toBytes(),
      this.label
    );
  }

  public static calculateValue(
    shares: number,
    paymentPeriods: number,
    maybeValue?: number,
    maybeRate?: number
  ): number {
    // Check for negative parameters
    // Rename some variables in order to have more understable error message.
    const inputs = {
      shares,
      paymentPeriods,
      value: maybeValue,
      rate: maybeRate,
    };
    for (const [inputName, inputValue] of Object.entries(inputs)) {
      if (inputValue && inputValue < 0) {
        throw Error(
          `Negative policy parameters are not allowed: ${inputName} is ${inputValue}`
        );
      }
    }

    // Check for missing parameters
    const hasNoValue = maybeValue === undefined || maybeValue === 0;
    const hasNoRate = maybeRate === undefined || maybeRate === 0;
    if (hasNoValue && hasNoRate) {
      throw Error(
        `Either 'value' or 'rate'  must be provided for policy. Got value: ${maybeValue} and rate: ${maybeRate}`
      );
    }

    const value = maybeValue
      ? maybeValue
      : (maybeRate as number) * paymentPeriods * shares;

    const valuePerNode = Math.floor(value / shares);
    if (valuePerNode * shares !== value) {
      throw Error(
        `Policy value of ${value} wei cannot be divided into ${shares} shares without a remainder.`
      );
    }

    const ratePerPeriod = Math.floor(valuePerNode / paymentPeriods);
    const recalculatedValue = ratePerPeriod * paymentPeriods * shares;
    if (recalculatedValue !== value) {
      throw Error(
        `Policy value of ${valuePerNode} wei per node cannot be divided by duration ` +
          `${paymentPeriods} periods without a remainder.`
      );
    }

    // At this point, we are only interested in value
    return value;
  }

  public async publish(ursulas: readonly ChecksumAddress[]): Promise<void> {
    const ownerAddress = await this.publisher.transactingPower.getAddress();
    await PolicyManagerAgent.createPolicy(
      this.publisher.transactingPower,
      this.hrac.toBytes(),
      this.value,
      (this.expiration.getTime() / 1000) | 0,
      ursulas,
      ownerAddress
    );
  }

  public async enact(ursulas: readonly Ursula[]): Promise<EnactedPolicy> {
    const ursulaAddresses = ursulas.map((u) => u.checksumAddress);
    await this.publish(ursulaAddresses);

    const treasureMap = await TreasureMap.constructByPublisher(
      this.hrac,
      this.publisher,
      ursulas,
      this.verifiedKFrags,
      this.threshold,
      this.delegatingKey
    );
    const encryptedTreasureMap = await this.encryptTreasureMap(treasureMap);
    const revocationKit = new RevocationKit(treasureMap, this.publisher.signer);

    return {
      id: this.hrac,
      label: this.label,
      policyKey: this.delegatingKey,
      encryptedTreasureMap,
      revocationKit,
      aliceVerifyingKey: this.publisher.verifyingKey.toBytes(),
      ursulas,
    };
  }

  private encryptTreasureMap(treasureMap: TreasureMap): EncryptedTreasureMap {
    return treasureMap.encrypt(this.publisher, this.bob.decryptingKey);
  }
}
