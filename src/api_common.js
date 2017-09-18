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
        @arg {number} [cpuEntropyBits = 128] gather additional entropy
            from a CPU mining algorithm.  Set to 0 for testing.
        @return {wif}

        @example ecc.randomKey()
    */
    randomKey: (cpuEntropyBits) => PrivateKey.randomKey(cpuEntropyBits).toString(),

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
    privateToPublic: wif => PrivateKey.fromWif(wif).toPublic().toString(),

    /**
        @arg {pubkey} pubkey - like EOSKey..
        @arg {string} [addressPrefix = config.address_prefix] - like EOS
        @return {boolean|string} true or error string

        @example ecc.isValidPublic(pubkey) === true
    */
    isValidPublic: (pubkey, addressPrefix) => {
        try {
            PublicKey.fromStringOrThrow(pubkey, addressPrefix)
            return true
        } catch(error) {
            return error
        }
    },

    /**
        @arg {wif} wif
        @return {boolean|string} true or error string

        @example ecc.isValidPrivate(wif) === true
    */
    isValidPrivate: (wif) => {
        try {
            PrivateKey.fromWif(wif)
            return true
        } catch(error) {
            return error
        }
    },

    /**
        Create a signature using data or a hash.

        @arg {string|Buffer} data
        @arg {wif|PrivateKey} privateKey
        @arg {boolean} [hashData = true] - sha256 hash data before signing
        @return {string} hex signature

        @example ecc.sign('I am alive', wif)
    */
    sign: (data, privateKey, hashData = true) =>
        Signature[hashData ? 'sign' : 'signHash'](data, privateKey).toHex(),

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

        @example ecc.sha256('I am alive') === '8a72..'
    */
    sha256: (data, encoding = 'hex') => hash.sha256(data, encoding)

}

module.exports = ecc
