import { Alice, Bob, SecretKey, Enrico } from '@nucypher/nucypher-ts';
import { ethers } from 'ethers';

const txtEncoder = new TextEncoder();

const config = {
  // Public Porter endpoint on Ibex network
  porterUri: 'https://porter-ibex.nucypher.community',
}

const makeAlice = (provider) => {
  const secretKey = SecretKey.fromBytes(txtEncoder.encode('fake-secret-key-32-bytes-alice-x'));
  return Alice.fromSecretKey(config, secretKey, provider);
};

const makeBob = () => {
  const secretKey = SecretKey.fromBytes(txtEncoder.encode('fake-secret-key-32-bytes-bob-xxx'));
  return Bob.fromSecretKey(config, secretKey);
};

const runExample = async () => {
  if (!window.ethereum) {
    console.error('You need to connect to the MetaMask extension');
  }

  const provider = new ethers.providers.Web3Provider(window.ethereum, 'any');
  await provider.send('eth_requestAccounts', []);

  // first create the encrypted message
  const label = 'Some Label'
  const plainTextMessage = 'Hello World'
  const alice = makeAlice(provider);
  const policyEncryptingKeyFromLabel = alice.getPolicyEncryptingKeyFromLabel(label)
  const enrico = new Enrico(policyEncryptingKeyFromLabel)
  const messageKit = enrico.encryptMessage(plainTextMessage)

  // meanwhile there is a Bob
  const bob = makeBob();
  const bobPublicKey = bob.verifyingKey

  // and bob gives his public key to alice
  const remoteBob = { verifyingKey: bobPublicKey, decryptingKey: bobPublicKey }

  // back to alice - she is now creating a policy
  const threshold = 1
  const shares = 1
  const startDate = new Date()
  const endDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30) // In 30 days
  const policyParams = { bob: remoteBob, label, threshold, shares, startDate, endDate }
  // We can just do Alice::grant to combine there steps:
  const rawPolicy = await alice.generatePreEnactedPolicy(policyParams)
  const policy = await rawPolicy.enact(alice)

  //The following info is made available to bob
  const policyEncryptingKey = policy.policyKey
  const aliceVerifyingKey = alice.verifyingKey
  const encryptedTreasureMap = policy.encryptedTreasureMap
  // as well as the messageKit

  //back to bob - he is retrieving and decrypting

  const retrievedMessage = await bob.retrieveAndDecrypt(
    policyEncryptingKey,
    aliceVerifyingKey,
    [messageKit],
    encryptedTreasureMap
  )
};

runExample();
