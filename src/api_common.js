const Aes = require("./aes")
const PrivateKey = require("./key_private")
const PublicKey = require("./key_public")
const Signature = require("./signature")
const key_utils = require("./key_utils")
const hash = require("./hash")

/**
    [Wallet Import Format](https://en.bitcoin.it/wiki/Wallet_import_format)
    @typedef {string} wif
*/
/**
    EOSKey..
    @typedef {string} pubkey
*/

/** @namespace */
const ecc = {
    /**
      Initialize by running some self-checking code.  This should take a
      second to gather additional CPU entropy used during private key
      generation.

      Initialization happens once even if called multiple times.

      @return {Promise}
    */
    initialize: PrivateKey.initialize,

    /**
      Does not pause to gather CPU entropy.
      @return {Promise<PrivateKey>} test key
    */
    unsafeRandomKey: () => (
      PrivateKey.unsafeRandomKey().then(key => key.toString())
    ),

    /**
        @arg {number} [cpuEntropyBits = 0] gather additional entropy
        from a CPU mining algorithm.  This will already happen once by
        default.

        @return {Promise<wif>}

        @example
ecc.randomKey().then(privateKey => {
  console.log('Private Key:\t', privateKey) // wif
  console.log('Public Key:\t', ecc.privateToPublic(privateKey)) // EOSkey...
})
    */
    randomKey: (cpuEntropyBits) => (
      PrivateKey.randomKey(cpuEntropyBits).then(key => key.toString())
    ),

    /**

        @arg {string} seed - any length string.  This is private.  The same
        seed produces the same private key every time.  At least 128 random
        bits should be used to produce a good private key.
        @return {wif}

        @example ecc.seedPrivate('secret') === wif
    */
    seedPrivate: seed => PrivateKey.fromSeed(seed).toString(),

    /**
        @arg {wif} wif
        @arg {string} [pubkey_prefix = 'EOS'] - public key prefix

        @return {pubkey}

        @example ecc.privateToPublic(wif) === pubkey
    */
    privateToPublic: (wif, pubkey_prefix = 'EOS') =>
      PrivateKey(wif).toPublic().toString(pubkey_prefix),

    /**
        @arg {pubkey} pubkey - like EOSKey..
        @arg {string} [pubkey_prefix = 'EOS']

        @return {boolean} valid

        @example ecc.isValidPublic(pubkey) === true
    */
    isValidPublic: (pubkey, pubkey_prefix = 'EOS') =>
      PublicKey.isValid(pubkey, pubkey_prefix),

    /**
        @arg {wif} wif
        @return {boolean} valid

        @example ecc.isValidPrivate(wif) === true
    */
    isValidPrivate: (wif) => PrivateKey.isValid(wif),

    /**
        Create a signature using data or a hash.

        @arg {string|Buffer} data
        @arg {wif|PrivateKey} privateKey
        @arg {String} [encoding = 'utf8'] - data encoding (if string)

        @return {string} string signature

        @example ecc.sign('I am alive', wif)
    */
    sign: (data, privateKey, encoding = 'utf8') => {
        if(encoding === true) {
          throw new TypeError('API changed, use signHash(..) instead')
        } else {
          if(encoding === false) {
            console.log('Warning: ecc.sign hashData parameter was removed');
          }
        }
        return Signature.sign(data, privateKey, encoding).toString()
    },

    /**
        @arg {String|Buffer} dataSha256 - sha256 hash 32 byte buffer or string
        @arg {wif|PrivateKey} privateKey
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

        @return {string} string signature
    */
    signHash: (dataSha256, privateKey, encoding = 'hex') => {
      return Signature.signHash(dataSha256, privateKey, encoding).toString()
    },

    /**
        Verify signed data.

        @arg {string|Buffer} signature - buffer or hex string
        @arg {string|Buffer} data
        @arg {pubkey|PublicKey} pubkey
        @arg {boolean} [hashData = true] - sha256 hash data before verify
        @return {boolean}

        @example ecc.verify(signature, 'I am alive', pubkey) === true
    */
    verify: (signature, data, pubkey, encoding = 'utf8') => {
        if(encoding === true) {
          throw new TypeError('API changed, use verifyHash(..) instead')
        } else {
          if(encoding === false) {
            console.log('Warning: ecc.verify hashData parameter was removed');
          }
        }
        signature = Signature.from(signature)
        return signature.verify(data, pubkey, encoding)
    },

    verifyHash(signature, dataSha256, pubkey, encoding = 'hex') {
      signature = Signature.from(signature)
      return signature.verifyHash(dataSha256, pubkey, encoding)
    },

    /**
        Recover the public key used to create the signature.

        @arg {String|Buffer} signature (EOSbase58sig.., Hex, Buffer)
        @arg {String|Buffer} data - full data
        @arg {String} [encoding = 'utf8'] - data encoding (if data is a string)

        @return {pubkey}

        @example ecc.recover(signature, 'I am alive') === pubkey
    */
    recover: (signature, data, encoding = 'utf8') => {
        if(encoding === true) {
          throw new TypeError('API changed, use recoverHash(signature, data) instead')
        } else {
          if(encoding === false) {
            console.log('Warning: ecc.recover hashData parameter was removed');
          }
        }
        signature = Signature.from(signature)
        return signature.recover(data, encoding).toString()
    },

    /**
        @arg {String|Buffer} signature (EOSbase58sig.., Hex, Buffer)
        @arg {String|Buffer} dataSha256 - sha256 hash 32 byte buffer or hex string
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if dataSha256 is a string)

        @return {PublicKey}
    */
    recoverHash: (signature, dataSha256, encoding = 'hex') => {
        signature = Signature.from(signature)
        return signature.recoverHash(dataSha256, encoding).toString()
    },

    /** @arg {string|Buffer} data - always binary, you may need Buffer.from(data, 'hex')
        @arg {string} [encoding = 'hex'] - result encoding 'hex', 'binary' or 'base64'
        @return {string|Buffer} - Buffer when encoding is null, or string

        @example ecc.sha256('hashme') === '02208b..'
        @example ecc.sha256(Buffer.from('02208b', 'hex')) === '29a23..'
    */
    sha256: (data, resultEncoding = 'hex') => hash.sha256(data, resultEncoding)
}

module.exports = ecc
