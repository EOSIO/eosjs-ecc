const Aes = require("./aes")
const PrivateKey = require("./key_private")
const PublicKey = require("./key_public")
const Signature = require("./signature")
const key_utils = require("./key_utils")
const config = require('./config')

module.exports = {
    /**
        @return {string} wif
    */
    randomKey: () => PrivateKey.randomKey().toString(),

    seedPrivate: seed => PrivateKey.fromSeed(seed).toString(),

    privateToPublic: wif => PrivateKey.fromWif(wif).toPublic().toString(),

    /** @return {boolean|string} true or error string */
    isValidPublic: (...args) => {
        try {
            PublicKey.fromStringOrThrow(...args)
            return true
        } catch(error) {
            return error
        }
    },

    /** @return {boolean|string} true or error string */
    isValidPrivate: (wif) => {
        try {
            PrivateKey.fromWif(wif)
            return true
        } catch(error) {
            return error
        }
    }
}


