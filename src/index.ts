import {
  checkExpiration,
  getCoseSign1Bech32Address,
  getPayload,
  verifyCoseSign1Address,
  verifyCoseSign1Signature,
} from './auth-utils';

export class Web3Authentication {
  constructor(private readonly expirationTimeSpan: number, private readonly hostname: string) {}

  public authenticate(
    url: string,
    action: string,
    key: string,
    signature: string,
    options: Web3AuthenticationOptions,
  ): { payload: Web3AuthenticationPayload; walletAddress: string } {
    const payload = getPayload(signature);

    if (!checkExpiration(payload, options.expirationTimeSpan ? options.expirationTimeSpan : this.expirationTimeSpan)) {
      throw new Web3AuthenticationError('Expired timestamp', 401);
    }

    if (action !== payload.action) {
      throw new Web3AuthenticationError('Invalid action', 401);
    }

    if (this.hostname + url !== payload.url) {
      throw new Web3AuthenticationError('Invalid url', 401);
    }

    if (!verifyCoseSign1Signature(key, signature)) {
      throw new Web3AuthenticationError('Invalid signature', 401);
    }

    if (!verifyCoseSign1Address(key, signature)) {
      throw new Web3AuthenticationError("Public key doesn't match the provided address", 401);
    }

    return { payload, walletAddress: getCoseSign1Bech32Address(signature) };
  }
}

export class Web3AuthenticationError extends Error {
  constructor(message: string, public httpErrorCode: number) {
    super(message);
    this.name = 'Web3AuthenticationError';
  }
}

export type Web3AuthenticationPayload = {
  url: string;
  action: string;
  timestamp: number;
  [property: string]: unknown;
};

export type Web3AuthenticationOptions = {
  expirationTimeSpan?: number;
};

export * as authUtils from './auth-utils';
export * as testUtils from './test-utils';
