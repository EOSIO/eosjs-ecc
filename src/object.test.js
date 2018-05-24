
/* eslint-env mocha */
const assert = require('assert')

const ecc = require('.')

const {PublicKey, PrivateKey, Signature} = ecc

describe('Object API', () => {
  const pvt = PrivateKey('5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3')
  const pub = pvt.toPublic()

  describe('secp256k1 keys', () => {
    it('randomKey', function() {
      this.timeout(1100)
      return PrivateKey.randomKey()
    })

    it('private to public', () => {
      assert.equal(
        pub.toString(),
        // 'PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63',
        'EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV',
        'pub.toString'
      )
    })

    it('PrivateKey constructors', () => {
      assert(pvt.toWif() === PrivateKey(pvt.toWif()).toWif())
      assert(pvt.toWif() === PrivateKey(pvt.toBuffer()).toWif())
      assert(pvt.toWif() === PrivateKey(pvt).toWif())

      // 01 suffix indicates a compressed public key (normally this is omitted)
      const pvtCompressFlag = Buffer.concat([pvt.toBuffer(), Buffer.from('01', 'hex')])
      assert(pvt.toWif() === PrivateKey(pvtCompressFlag).toWif())

      assert.throws(() => PrivateKey(), /Invalid private key/)
      assert.throws(() => PrivateKey.fromHex('ff'), /Expecting 32 bytes/)
      assert.throws(() => PrivateKey.fromBuffer('ff'), /Expecting parameter to be a Buffer type/)
      assert.doesNotThrow(() => {
        PrivateKey('PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd')
      })
    })

    it('Helpers', () => {
      assert.equal(PrivateKey.isWif('5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3'), true, 'isWif')
      assert.equal(PrivateKey.isWif('PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd'), false, 'isWif')
    })

    it('PublicKey constructors', () => {
      assert(pub.toString() === PublicKey(pub.toString()).toString())
      assert(pub.toString() === PublicKey(pub.toBuffer()).toString())
      assert(pub.toString() === PublicKey(pub).toString())
      assert.throws(() => PublicKey(), /Invalid public key/)
    })
  })

  /** @todo secp224r1 */
  // it('PrivateKey secp224r1', () => {
  //   const pvt = PrivateKey('PVT_K1_iyQmnyPEGvFd8uffnk152WC2WryBjgTrg22fXQryuGL9mU6qW')
  //   const pub = pvt.toPublic()
  //
  //   assert.equal(
  //     pub.toString(),
  //     'PUB_K1_6EPHFSKVYHBjQgxVGQPrwCxTg7BbZ69H9i4gztN9deKTEXYne4',
  //     'toString'
  //   )
  // })

  it('Signature', () => {
    const sig = Signature.sign('data', pvt)
    const sigString = sig.toString()
    assert.equal(sig.toString(), sigString, 'cache')
    assert.equal(Signature.fromString(sigString).toString(), sigString, 'fromString')
    assert(sigString.length > 90, 'signature string is too short')
    assert(Signature.from(sigString), 'signature from string')
  })
})
