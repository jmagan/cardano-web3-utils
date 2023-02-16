import CSL from '@emurgo/cardano-serialization-lib-nodejs';
import MSG from '@emurgo/cardano-message-signing-nodejs';

/**
 * Create a COSE Key structure from a private key
 *
 * @param {CSL.PrivateKey} privateKey - private key to extract the public key
 * @returns
 */
export function createCOSEKey(privateKey: CSL.PrivateKey) {
  const coseKey = MSG.COSEKey.new(MSG.Label.new_int(MSG.Int.new_i32(1)));
  coseKey.set_header(
    MSG.Label.new_int(MSG.Int.new_negative(MSG.BigNum.from_str('2'))),
    MSG.CBORValue.new_bytes(privateKey.to_public().as_bytes()),
  );
  return coseKey;
}

export function createCOSESign1Signature(payload: object, address: CSL.RewardAddress, privateKey: CSL.PrivateKey) {
  const protectedHeaders = MSG.HeaderMap.new();
  protectedHeaders.set_header(MSG.Label.new_text('address'), MSG.CBORValue.new_bytes(address.to_address().to_bytes()));
  const protectedHeadersSerialized = MSG.ProtectedHeaderMap.new(protectedHeaders);
  const headers = MSG.Headers.new(protectedHeadersSerialized, MSG.HeaderMap.new());
  const builder = MSG.COSESign1Builder.new(headers, Buffer.from(JSON.stringify(payload)), false);
  const toSign = builder.make_data_to_sign().to_bytes();
  const signedSignature = privateKey.sign(toSign).to_bytes();

  return builder.build(signedSignature);
}

/**
 *
 * @param {number} accountNumber - Number between 0 and 255 for mocking private key
 * @returns
 */
export function createFakePrivateKey(accountNumber: number) {
  return CSL.PrivateKey.from_normal_bytes(new Uint8Array(new Array(32).fill(accountNumber)));
}

/**
 *
 * @param {CSL.PrivateKey} privateKey
 * @param {CSL.NetworkId} networkId
 * @returns
 */
export function createRewardAddress(privateKey: CSL.PrivateKey, networkId: CSL.NetworkId) {
  const _networkId = networkId ? networkId : CSL.NetworkId.mainnet();
  return CSL.RewardAddress.new(_networkId.kind(), CSL.StakeCredential.from_keyhash(privateKey.to_public().hash()));
}
