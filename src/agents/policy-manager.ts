import { ContractTransaction, ethers } from 'ethers';
import { hexlify } from 'ethers/lib/utils';

import {
  PolicyManager,
  PolicyManager__factory,
} from '../../types/ethers-contracts';
import { TransactingPower } from '../crypto/powers';
import { ChecksumAddress } from '../types';
import { toHexString } from '../utils';

import { CONTRACTS, DEFAULT_WAIT_N_CONFIRMATIONS } from './constants';

export class PolicyManagerAgent {
  public static async createPolicy(
    transactingPower: TransactingPower,
    policyId: Uint8Array,
    valueInWei: number,
    expirationTimestamp: number,
    nodeAddresses: readonly ChecksumAddress[],
    ownerAddress: ChecksumAddress
  ): Promise<ContractTransaction> {
    const PolicyManager = await this.connect(
      transactingPower.provider,
      transactingPower.signer
    );
    // TODO: Call fails due to "UNPREDICTABLE_GAS_LIMIT" error, hard-coding `gasLimit` for now
    // const estimatedGas = await PolicyManager.estimateGas.createPolicy(
    //   policyId,
    //   ownerAddress,
    //   expirationTimestamp,
    //   nodeAddresses
    // );
    const overrides = {
      // gasLimit: estimatedGas.toNumber(),
      gasLimit: 350_000,
      value: BigInt(valueInWei),
    };
    const tx = await PolicyManager.createPolicy(
      hexlify(policyId),
      ownerAddress,
      expirationTimestamp,
      nodeAddresses as ChecksumAddress[], // Must pass as mutable
      overrides
    );
    await tx.wait(DEFAULT_WAIT_N_CONFIRMATIONS);
    return tx;
  }

  public static async isPolicyDisabled(
    provider: ethers.providers.Provider,
    policyId: Uint8Array
  ): Promise<boolean> {
    const PolicyManager = await this.connect(provider);
    const policy = await PolicyManager.policies(policyId);
    if (!policy) {
      throw Error(`Policy with id ${toHexString(policyId)} does not exist.`);
    }
    return policy.disabled;
  }

  public static async getGlobalMinRate(
    provider: ethers.providers.Provider
  ): Promise<number> {
    const PolicyManager = await this.connect(provider);
    const feeRateRange = await PolicyManager.feeRateRange();
    return feeRateRange.min.toNumber();
  }

  public static async revokePolicy(
    transactingPower: TransactingPower,
    policyId: Uint8Array
  ): Promise<ContractTransaction> {
    const PolicyManager = await this.connect(
      transactingPower.provider,
      transactingPower.signer
    );
    const estimatedGas = await PolicyManager.estimateGas.revokePolicy(policyId);
    const overrides = {
      gasLimit: estimatedGas.toNumber(),
    };
    const tx = await PolicyManager.revokePolicy(hexlify(policyId), overrides);
    await tx.wait(DEFAULT_WAIT_N_CONFIRMATIONS);
    return tx;
  }

  private static async connect(
    provider: ethers.providers.Provider,
    signer?: ethers.providers.JsonRpcSigner
  ): Promise<PolicyManager> {
    const network = await provider.getNetwork();
    const contractAddress = CONTRACTS[network.name].POLICYMANAGER;
    return PolicyManager__factory.connect(contractAddress, signer ?? provider);
  }
}
