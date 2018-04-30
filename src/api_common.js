const Aes = require("./aes")
const PrivateKey = require("./key_private")
const PublicKey = require("./key_public")
const Signature = require("./signature")
const key_utils = require("./key_utils")
const config = require('./config')
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
        @return {pubkey}

        @example ecc.privateToPublic(wif) === pubkey
    */
    privateToPublic: wif => PrivateKey(wif).toPublic().toString(),

    /**
        @arg {pubkey} pubkey - like EOSKey..
        @return {boolean} valid

        @example ecc.isValidPublic(pubkey) === true
    */
    isValidPublic: (pubkey) => PublicKey.isValid(pubkey),

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
        @arg {boolean} [hashData = true] - sha256 hash data before signing
        @return {string} string signature

        @example ecc.sign('I am alive', wif)
    */
    sign: (data, privateKey, hashData = true) =>
        Signature[hashData ? 'sign' : 'signHash'](data, privateKey).toString(),

    /**
        Verify signed data.

        @arg {string|Buffer} signature - buffer or hex string
        @arg {string|Buffer} data
        @arg {pubkey|PublicKey} pubkey
        @arg {boolean} [hashData = true] - sha256 hash data before verify
        @return {boolean}

        @example ecc.verify(signature, 'I am alive', pubkey) === true
    */
    verify: (signature, data, pubkey, hashData = true) => {
        signature = Signature.from(signature)
        const verify = signature[hashData ? 'verify' : 'verifyHash']
        return verify(data, pubkey)
    },

    /**
        Recover the public key used to create the signature.

        @arg {String} signature (hex, etc..)
        @arg {String|Buffer} data
        @arg {boolean} [hashData = true] - sha256 hash data before recover
        @return {pubkey}

        @example ecc.recover(signature, 'I am alive') === pubkey
    */
    recover: (signature, data, hashData = true) => {
        signature = Signature.from(signature)
        const recover = signature[hashData ? 'recover' : 'recoverHash']
        return recover(data).toString()
    },

    /** @arg {string|Buffer} data
        @arg {string} [encoding = 'hex'] - 'hex', 'binary' or 'base64'
        @return {string|Buffer} - Buffer when encoding is null, or string

        @example ecc.sha256('hashme') === '02208b..'
    */
    sha256: (data, encoding = 'hex') => hash.sha256(data, encoding)
}

module.exports = ecc
