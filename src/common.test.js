/* eslint-env mocha */
const assert = require('assert')

const ecc = require('.')

const wif = '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'

describe('Common API', () => {
  it('unsafeRandomKey', async function() {
    const pvt = await ecc.unsafeRandomKey()
    assert.equal(typeof pvt, 'string', 'pvt')
    assert(/^5[HJK]/.test(wif))
    // assert(/^PVT_K1_/.test(pvt)) // todo
  })

  it('seedPrivate', () => {
    assert.equal(ecc.seedPrivate(''), wif)
    // assert.equal(ecc.seedPrivate(''), 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd')
  })

  it('privateToPublic', () => {
    // const pub = 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX'
    const pub = 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'
    assert.equal(ecc.privateToPublic(wif), pub)
  })

  it('isValidPublic', () => {
    const keys = [
      [true, 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX'],
      [true, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'],
      [false, 'MMM859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'],
      [false, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'EOS'],
      [true, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'PUB'],
      [false, 'PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'PUB'],
    ]
    for(const key of keys) {
      const [valid, pubkey, prefix] = key
      assert.equal(valid, ecc.isValidPublic(pubkey, prefix), pubkey)
    }
  })

  it('isValidPrivate', () => {
    const keys = [
      [true, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'],
      [false, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm'],
    ]
    for(const key of keys) {
      assert.equal(key[0], ecc.isValidPrivate(key[1]), key[1])
    }
  })

  it('hashs', () => {
    const hashes = [
      // ['sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ]
    for(const hash of hashes) {
      assert.equal(ecc[hash[0]](''), hash[1])
      assert.equal(ecc[hash[0]](Buffer.from('')), hash[1])
    }
  })

  it('signatures', () => {
    const pvt = ecc.seedPrivate('')
    const pubkey = ecc.privateToPublic(pvt)

    const data = 'hi'
    const dataSha256 = ecc.sha256(data)

    const sigs = [
      ecc.sign(data, pvt),
      ecc.signHash(dataSha256, pvt)
    ]

    for(const sig of sigs) {
      assert(ecc.verify(sig, data, pubkey), 'verify data')
      assert(ecc.verifyHash(sig, dataSha256, pubkey), 'verify hash')
      assert.equal(pubkey, ecc.recover(sig, data), 'recover from data')
      assert.equal(pubkey, ecc.recoverHash(sig, dataSha256), 'recover from hash')
    }
  })
})

describe('Common API (initialized)', () => {
  it('initialize', () => ecc.initialize())

  it('randomKey', () => {
    const cpuEntropyBits = 1
    ecc.key_utils.addEntropy(1, 2, 3)
    const pvt = ecc.unsafeRandomKey().then(pvt => {
      assert.equal(typeof pvt, 'string', 'pvt')
      assert(/^5[HJK]/.test(wif))
      // assert(/^PVT_K1_/.test(pvt))
    })
  })
})
