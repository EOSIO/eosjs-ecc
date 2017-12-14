
/* eslint-env mocha */
const assert = require('assert')

const ecc = require('.')

const {PublicKey, PrivateKey} = ecc

describe('Object API', () => {
  it('PrivateKey constructor', () => {
    PrivateKey.randomKey().then(privateKey => {
      assert(privateKey.toWif() === PrivateKey(privateKey.toWif()).toWif())
      assert(privateKey.toWif() === PrivateKey(privateKey.toBuffer()).toWif())
      assert(privateKey.toWif() === PrivateKey(privateKey).toWif())
      assert.throws(() => PrivateKey(), /Invalid private key/)
    })
  })

  it('PublicKey constructor', () => {
    PrivateKey.randomKey().then(privateKey => {
      const publicKey = privateKey.toPublic()
      assert(publicKey.toString() === PublicKey(publicKey.toString()).toString())
      assert(publicKey.toString() === PublicKey(publicKey.toBuffer()).toString())
      assert(publicKey.toString() === PublicKey(publicKey).toString())
      assert.throws(() => PublicKey(), /Invalid public key/)
    })
  })
})
