import { SecretKey } from '@nucypher/nucypher-core';

import { conditions } from '../../src';
import { ContractCondition } from '../../src/conditions/base';
import { fakeWeb3Provider } from '../utils';

import { aliceSecretKeyBytes } from './testVariables';

const { ConditionExpression } = conditions;

const aliceSecretKey = SecretKey.fromBEBytes(aliceSecretKeyBytes);
const web3Provider = fakeWeb3Provider(aliceSecretKey.toBEBytes());
const condition = new ContractCondition({
  chain: 80001,
  contractAddress: '0xdc6e2b14260f972ad4e5a31c68294fba7e720701',
  functionAbi: {
    inputs: [{ internalType: 'bytes', name: 'swapHash', type: 'bytes' }],
    name: 'isDeposited',
    outputs: [{ internalType: 'bool', name: 'result', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  method: 'isDeposited',
  parameters: [
    '0x7c7c7962a263b2882e5376ebb00bdb996baf5d2038b701d12c210df488a5c7a6',
  ],
  returnValueTest: { comparator: '==', value: true },
});

describe('reproducing error', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('builds context from condition', async () => {
    await new ConditionExpression(condition)
      .buildContext(web3Provider)
      .toJson();
  });
});
