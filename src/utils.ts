import CSL from '@emurgo/cardano-serialization-lib-nodejs';
import MSG from '@emurgo/cardano-message-signing-nodejs';
import { Web3AuthenticationPayload } from '.';

export function checkExpiration(payload: Web3AuthenticationPayload, expirationTimeSpan: number) {
  if (!payload.timestamp || !Number.isInteger(payload.timestamp)) {
    throw Error('Invalid or missing timestamp');
  }

  if (payload.timestamp > Date.now() || payload.timestamp < Date.now() - expirationTimeSpan * 1000) {
    return false;
  }

  return true;
}

/**
 * Get the bech32 address from a COSE_Sign1 signature
 * @param {String} signature - Hex string represeantation of a COSE_Sign1 signature
 */
export function getCoseSign1Bech32Address(signature: string) {
  const coseSignature = MSG.COSESign1.from_bytes(Buffer.from(signature, 'hex'));

  const addressHeader = coseSignature
    .headers()
    .protected()
    .deserialized_headers()
    .header(MSG.Label.new_text('address'));

  if (addressHeader === undefined) {
    throw Error('Address header not found');
  }

  const bAddress = addressHeader.as_bytes();

  if (bAddress === undefined) {
    throw Error('Error decoding signature address');
  }

  const address = CSL.Address.from_bytes(bAddress);

  return address.to_bech32();
}

/**
 *
 * @param {String} signature
 */
export function getPayload(signature: string) {
  const coseSign1 = MSG.COSESign1.from_bytes(Buffer.from(signature, 'hex'));

  const bPayload = coseSign1.payload();

  if (bPayload === undefined) {
    throw new Error('Payload missing');
  }

  const payload = JSON.parse(Buffer.from(bPayload).toString()) as Web3AuthenticationPayload;

  if (payload.action === undefined || payload.timestamp === undefined || payload.url === undefined) {
    throw new Error('Invalid payload');
  }

  return payload;
}

export function verifyCoseSign1Address(key: string, signature: string) {
  const coseKey = MSG.COSEKey.from_bytes(Buffer.from(key, 'hex'));

  const keyHeader = coseKey.header(MSG.Label.new_int(MSG.Int.new_negative(MSG.BigNum.from_str('2'))));

  if (keyHeader === undefined) {
    throw new Error('Key header not found');
  }

  const bKey = keyHeader.as_bytes();

  if (bKey === undefined) {
    throw new Error('Error decoding key signature');
  }

  const publicKey = CSL.PublicKey.from_bytes(bKey);

  const bech32SigAddress = getCoseSign1Bech32Address(signature);

  const address = CSL.RewardAddress.from_address(CSL.Address.from_bech32(bech32SigAddress));

  if (address === undefined) {
    throw new Error('Address is not a reward address');
  }
  const signatureKeyHash = address.payment_cred().to_keyhash();
  if (signatureKeyHash === undefined) {
    throw new Error('Invalid signature key hash');
  }

  const publicKeyHash = publicKey.hash();

  return signatureKeyHash.to_hex() === publicKeyHash.to_hex();
}

export function verifyCoseSign1Signature(key: string, signature: string) {
  const coseSignature = MSG.COSESign1.from_bytes(Buffer.from(signature, 'hex'));

  const coseKey = MSG.COSEKey.from_bytes(Buffer.from(key, 'hex'));

  const keyHeader = coseKey.header(MSG.Label.new_int(MSG.Int.new_negative(MSG.BigNum.from_str('2'))));

  if (keyHeader === undefined) {
    throw new Error('Key header not found');
  }

  const bKey = keyHeader.as_bytes();

  if (bKey === undefined) {
    throw new Error('Error decoding key signature');
  }

  const publicKey = CSL.PublicKey.from_bytes(bKey);

  const signedPayload = coseSignature.signed_data().to_bytes();

  const ed25519Signature = CSL.Ed25519Signature.from_bytes(coseSignature.signature());

  return publicKey.verify(signedPayload, ed25519Signature);
}
