
/* eslint-env mocha */
const assert = require('assert')
const config = require('./config');

const ecc = require('.')

const {PublicKey, PrivateKey, Signature} = ecc

describe('Object API', () => {
  it('PrivateKey constructor', () => {
    return PrivateKey.randomKey().then(privateKey => {
      assert(privateKey.toWif() === PrivateKey(privateKey.toWif()).toWif())
      assert(privateKey.toWif() === PrivateKey(privateKey.toBuffer()).toWif())
      assert(privateKey.toWif() === PrivateKey(privateKey).toWif())
      assert.throws(() => PrivateKey(), /Invalid private key/)
    })
  })

  it('PublicKey constructor', () => {
    return PrivateKey.randomKey().then(privateKey => {
      const publicKey = privateKey.toPublic()
      assert(publicKey.toString() === PublicKey(publicKey.toString()).toString())
      assert(publicKey.toString() === PublicKey(publicKey.toBuffer()).toString())
      assert(publicKey.toString() === PublicKey(publicKey).toString())
      assert.throws(() => PublicKey(), /Invalid public key/)
    })
  })
  it('Signature', () => {
    return PrivateKey.randomKey().then(privateKey => {
      const signature = Signature.sign('data', privateKey)
      const sigstr = signature.toString()
      assert.equal(signature.toString(), sigstr, 'cache')
      assert.equal(Signature.fromString(sigstr).toString(), sigstr, 'fromString')
      assert(sigstr.length > 90, 'signature string is too short')
      assert(Signature.from(sigstr), 'signature from string')
    })
  })
})
