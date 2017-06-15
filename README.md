# Elliptic curve cryptography functions (ECC)
Private Key, Public Key, Signature, AES, Encryption / Decryption

## Usage (Node)

```bash
npm i eos-ecc
```

```js
const {PrivateKey, PublicKey, Signature, Aes} = require('eos-ecc')

// Create a new random private key
privateWif = PrivateKey.randomKey().toWif()


// Convert to a public key
pubkey = PrivateKey.fromWif(privateWif).toPublic().toString()

```

## Browser (build eos_ecc.js below)

```html
<script src=eos_ecc.js></script>
```

```js
var {PrivateKey} = eos_ecc
var privateWif = PrivateKey.randomKey().toWif()
var pubkey = PrivateKey.fromWif(privateWif).toPublic().toString()
console.log(pubkey)
```

## Configure

```js
const {config} = require('eos-ecc')

// Change the public key address prefix
// config.address_prefix = 'XXX'

```
See [Config](./src/config.js)


## See Also

* [PrivateKey](./src/key_private.js)
* [PublicKey](./src/key_public.js)
* [Signature](./src/signature.js)
* [Aes](./src/aes.js)

## Build

Dependencies: Unix like OS, sha256sum

```bash
git clone https://github.com/eosjs/ecc.git
cd ecc
yarn
yarn build
# builds: ./dist/eos_ecc.js
# Verify release hash
```

## Releases

* v1.0.0 - sha256 3f8ae6c183f18cd4a6e6b5a7fac2958a3a4071f2abe6dc0286dc30e10068851b
