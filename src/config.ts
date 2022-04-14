import { ChainId } from './types';

export interface Configuration {
  porterUri: string;
}

const CONFIGS: { [key in ChainId]: Configuration } = {
  [ChainId.POLYGON]: {
    porterUri: 'https://porter.nucypher.community',
  },
  [ChainId.MUMBAI]: {
    porterUri: 'https://porter-ibex.nucypher.community',
  },
};

export const defaultConfiguration = (chainId: number): Configuration => {
  if (!Object.values(ChainId).includes(chainId)) {
    throw new Error(`No default configuration found for chainId: ${chainId}`);
  }
  return CONFIGS[chainId as ChainId];
};
