
/* eslint-env mocha */
assert = require('assert')

ecc = require('.')

const {PublicKey, PrivateKey} = ecc

describe('Object API', () => {
  it('PrivateKey constructor', () => {
    privateKey = PrivateKey.randomKey({cpuEntropyBits: 0})
    assert(privateKey.toWif() === PrivateKey(privateKey.toWif()).toWif())
    assert(privateKey.toWif() === PrivateKey(privateKey.toBuffer()).toWif())
    assert(privateKey.toWif() === PrivateKey(privateKey).toWif())
    assert.throws(() => PrivateKey(), /Invalid private key/)
  })

  it('PublicKey constructor', () => {
    publicKey = PrivateKey.randomKey({cpuEntropyBits: 0}).toPublic()
    assert(publicKey.toString() === PublicKey(publicKey.toString()).toString())
    assert(publicKey.toString() === PublicKey(publicKey.toBuffer()).toString())
    assert(publicKey.toString() === PublicKey(publicKey).toString())
    assert.throws(() => PublicKey(), /Invalid public key/)
  })
})