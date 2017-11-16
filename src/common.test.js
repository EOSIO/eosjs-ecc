/* eslint-env mocha */
assert = require('assert')

ecc = require('.')

describe('Common API', () => {
  it('randomKey', () => {
    cpuEntropyBits = 1
    ecc.key_utils.addEntropy(1, 2, 3)
    assert(/^5[HJK]/.test(ecc.randomKey(cpuEntropyBits)))
  })

  it('seedPrivate', () => {
    wif = '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'
    assert.equal(ecc.seedPrivate(''), wif)
  })

  it('privateToPublic', () => {
    pub = 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'
    assert.equal(ecc.privateToPublic(wif), pub)
  })

  it('isValidPublic', () => {
    keys = [
      [true, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'],
      [false, 'MMM859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'],
      [false, 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhTo'],
    ]
    for(const key of keys) {
      assert.equal(key[0], ecc.isValidPublic(key[1]), key[1])
    }
  })

  it('isValidPrivate', () => {
    keys = [
      [true, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'],
      [false, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm'],
    ]
    for(const key of keys) {
      assert.equal(key[0], ecc.isValidPrivate(key[1]), key[1])
    }
  })

  it('hashs', () => {
    hashes = [
      // ['sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ]
    for(hash of hashes) {
      assert.equal(ecc[hash[0]](''), hash[1])
      assert.equal(ecc[hash[0]](Buffer.from('')), hash[1])
    }
  })

  it('signatures', () => {
    wif = ecc.seedPrivate('')
    pubkey = ecc.privateToPublic(wif)

    data = 'hi'
    dataSha256 = ecc.sha256(data)

    sigs = [
      ecc.sign(data, wif),
      ecc.sign(dataSha256, wif, false)
    ]

    for(sig of sigs) {
      assert.equal(65, Buffer.from(sig, 'hex').length)
      assert(ecc.verify(sig, data, pubkey), 'verify data')
      assert(ecc.verify(sig, dataSha256, pubkey, false), 'verify hash')
      assert.equal(pubkey, ecc.recover(sig, data), 'recover from data')
      assert.equal(pubkey, ecc.recover(sig, dataSha256, false), 'recover from hash')
    }
  })
})
