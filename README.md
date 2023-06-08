# Cardano web3 utils

Cardano web3 is a javascript library that allows interaction with COSE Sign1 and CBOR encoded data and implements some helper methods for CIP-0093 Authenticated HTTP Web3 Requests.

## API

### Web3Authentication

The `Web3Authentication` class provides authentication functionality. It has the following constructor and methods:
#### Constructor

* `Web3Authentication(expirationTimeSpan: number, hostname: string)`: Creates a new instance of the Web3Authentication class. It takes the expiration time span in seconds and the hostname as parameters.
#### Methods

* `authenticate<T>(uri: string, action: string, key: string, signature: string, options?: Web3AuthenticationOptions): { payload: Web3AuthenticationPayload & T; walletAddress: string }`: Performs authentication using the provided parameters. It returns an object with the authenticated payload and wallet address.
### Web3AuthenticationError

The `Web3AuthenticationError` class is an error subclass that represents authentication errors. It extends the built-in Error class and includes an additional property httpErrorCode to store the associated HTTP error code.

### Web3AuthenticationPayload

The `Web3AuthenticationPayload` type defines the structure of the payload used in the authentication process. It includes properties such as uri, action, timestamp, and optional properties for additional secured data.

## Utils


### Auth-utils

* `checkExpiration(payload: Web3AuthenticationPayload, expirationTimeSpan: number)`:
Checks if a payload has expired based on its timestamp and expiration time span.

* `getCoseSign1Bech32Address(signature: string)`: Extracts the bech32 address from a COSE_Sign1 signature.

* `getPayload(signature: string)`: Retrieves the payload from a COSE_Sign1 signature.

* `verifyCoseSign1Address(key: string, signature: string)`: Verifies if a COSE_Sign1 address matches the provided key.

* `verifyCoseSign1Signature(key: string, signature: string)`
Verifies the integrity of a COSE_Sign1 signature using the provided key.

## Test-utils

* `createCOSEKey(privateKey: CSL.PrivateKey)`: Creates a COSE Key structure from a private key.

* `createCOSESign1Signature(payload: object, address: CSL.RewardAddress, privateKey: CSL.PrivateKey)`: Creates a COSE_Sign1 signature using the provided payload, address, and private key.

* `createFakePrivateKey(accountNumber: number)`: Creates a fake private key for mocking purposes.

* `createRewardAddress(privateKey: CSL.PrivateKey, networkId: CSL.NetworkId)`: Creates a reward address from a private key and network ID.