var bip66 = require('bip66')
var bufferutils = require('./bufferutils')
var ECPair = require('./ecpair')
var typeforce = require('typeforce')
var types = require('./types')
var OPS = require('./opcodes')
var scriptTypes = {
  P2PKH: 'pubkeyhash',
  P2PK: 'pubkey',
  MULTISIG: 'multisig',
  P2SH: 'scripthash',
  P2WSH: 'segwitscripthash',
  P2WPKH: 'segwitpubkeyhash',
  NULLDATA: 'nulldata',
  NONSTANDARD: 'nonstandard'
}
var REVERSE_OPS = (function () {
  var result = {}
  for (var op in OPS) {
    var code = OPS[op]
    result[code] = op
  }
  return result
})()

var OP_INT_BASE = OPS.OP_RESERVED // OP_1 - 1

function toASM (chunks) {
  if (Buffer.isBuffer(chunks)) {
    chunks = decompile(chunks)
  }

  return chunks.map(function (chunk) {
    // data?
    if (Buffer.isBuffer(chunk)) return chunk.toString('hex')

    // opcode!
    return REVERSE_OPS[chunk]
  }).join(' ')
}

function fromASM (asm) {
  typeforce(types.String, asm)

  return compile(asm.split(' ').map(function (chunkStr) {
    // opcode?
    if (OPS[chunkStr] !== undefined) return OPS[chunkStr]

    // data!
    return new Buffer(chunkStr, 'hex')
  }))
}

function compile (chunks) {
  // TODO: remove me
  if (Buffer.isBuffer(chunks)) return chunks

  typeforce(types.Array, chunks)

  var bufferSize = chunks.reduce(function (accum, chunk) {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      return accum + bufferutils.pushDataSize(chunk.length) + chunk.length
    }

    // opcode
    return accum + 1
  }, 0.0)

  var buffer = new Buffer(bufferSize)
  var offset = 0

  chunks.forEach(function (chunk) {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      offset += bufferutils.writePushDataInt(buffer, chunk.length, offset)

      chunk.copy(buffer, offset)
      offset += chunk.length

    // opcode
    } else {
      buffer.writeUInt8(chunk, offset)
      offset += 1
    }
  })

  if (offset !== buffer.length) throw new Error('Could not decode chunks')
  return buffer
}

function decompile (buffer) {
  // TODO: remove me
  if (types.Array(buffer)) return buffer

  typeforce(types.Buffer, buffer)

  var chunks = []
  var i = 0

  while (i < buffer.length) {
    var opcode = buffer[i]

    // data chunk
    if ((opcode > OPS.OP_0) && (opcode <= OPS.OP_PUSHDATA4)) {
      var d = bufferutils.readPushDataInt(buffer, i)

      // did reading a pushDataInt fail? empty script
      if (d === null) return []
      i += d.size

      // attempt to read too much data? empty script
      if (i + d.number > buffer.length) return []

      var data = buffer.slice(i, i + d.number)
      i += d.number

      chunks.push(data)

    // opcode
    } else {
      chunks.push(opcode)

      i += 1
    }
  }

  return chunks
}

function isCanonicalPubKey (buffer) {
  if (!Buffer.isBuffer(buffer)) return false
  if (buffer.length < 33) return false

  switch (buffer[0]) {
    case 0x02:
    case 0x03:
      return buffer.length === 33
    case 0x04:
      return buffer.length === 65
  }

  return false
}

function isCanonicalSignature (buffer) {
  if (!Buffer.isBuffer(buffer)) return false
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false

  return bip66.check(buffer.slice(0, -1))
}

function isDefinedHashType (hashType) {
  var hashTypeMod = hashType & ~0x80

// return hashTypeMod > SIGHASH_ALL && hashTypeMod < SIGHASH_SINGLE
  return hashTypeMod > 0x00 && hashTypeMod < 0x04
}

function isPubKeyHashInput (script) {
  var chunks = decompile(script)

  return chunks.length === 2 &&
    isCanonicalSignature(chunks[0]) &&
    isCanonicalPubKey(chunks[1])
}

function isPubKeyHashOutput (script) {
  var buffer = compile(script)

  return buffer.length === 25 &&
    buffer[0] === OPS.OP_DUP &&
    buffer[1] === OPS.OP_HASH160 &&
    buffer[2] === 0x14 &&
    buffer[23] === OPS.OP_EQUALVERIFY &&
    buffer[24] === OPS.OP_CHECKSIG
}

function isSegWitPubKeyHashOutput (script) {
  var buffer = compile(script)

  return buffer.length === 22 &&
      buffer[0] === OPS.OP_0 &&
      buffer[1] === 0x14
}

function isPubKeyInput (script) {
  var chunks = decompile(script)

  return chunks.length === 1 &&
    isCanonicalSignature(chunks[0])
}

function isPubKeyOutput (script) {
  var chunks = decompile(script)

  return chunks.length === 2 &&
    isCanonicalPubKey(chunks[0]) &&
    chunks[1] === OPS.OP_CHECKSIG
}

function isScriptHashInput (script, allowIncomplete) {
  var chunks = decompile(script)
  if (chunks.length < 2) return false

  var lastChunk = chunks[chunks.length - 1]
  if (!Buffer.isBuffer(lastChunk)) return false

  var scriptSigChunks = chunks.slice(0, -1)
  var redeemScriptChunks = decompile(lastChunk)

  // is redeemScript a valid script?
  if (redeemScriptChunks.length === 0) return false

  var inputType = classifyInput(scriptSigChunks, allowIncomplete)
  var outputType = classifyOutput(redeemScriptChunks)

  if (outputType === scriptTypes.P2WPKH) {
    return inputType === scriptTypes.P2PKH
  }

  return inputType === outputType
}

function isScriptHashOutput (script) {
  var buffer = compile(script)

  return buffer.length === 23 &&
    buffer[0] === OPS.OP_HASH160 &&
    buffer[1] === 0x14 &&
    buffer[22] === OPS.OP_EQUAL
}

function isSegWitScriptHashOutput (script) {
  var buffer = compile(script)

  return buffer.length === 34 &&
    buffer[0] === OPS.OP_0 &&
    buffer[1] === 0x20
}

// allowIncomplete is to account for combining signatures
// See https://github.com/bitcoin/bitcoin/blob/f425050546644a36b0b8e0eb2f6934a3e0f6f80f/src/script/sign.cpp#L195-L197
function isMultisigInput (script, allowIncomplete) {
  var chunks = decompile(script)
  if (chunks.length < 2) return false
  if (chunks[0] !== OPS.OP_0) return false

  if (allowIncomplete) {
    return chunks.slice(1).every(function (chunk) {
      return chunk === OPS.OP_0 || isCanonicalSignature(chunk)
    })
  }

  return chunks.slice(1).every(isCanonicalSignature)
}

function parseMultisigScript (chunks) {
  typeforce(types.tuple(types.maybe(types.Number), types.maybe(types.Buffer)), chunks)
  if (chunks.length < 4) {
    throw new Error('Multsig script is missing elements')
  }

  if (!types.Number(chunks[0])) {
    throw new Error('number of signatures must be an opcode')
  }
  chunks.slice(1, chunks.length - 2).forEach(function (element) {
    if (!types.Buffer(element)) {
      throw new Error('public keys must be an opcode')
    }
  })
  if (!types.Number(chunks[chunks.length - 2])) {
    throw new Error('number of public keys must be an opcode')
  }
  if (chunks[chunks.length - 1] !== OPS.OP_CHECKMULTISIG) {
    throw new Error('last opcode must be OP_CHECKMULTISIG')
  }

  var m = chunks[0] - OP_INT_BASE
  var n = chunks[chunks.length - 2] - OP_INT_BASE
  if (m < 0) {
    throw new Error('number of signatures cannot be less than zero')
  }
  if (m > n) {
    throw new Error('number of signatures cannot exceed number of public keys')
  }
  if (n > 16) {
    throw new Error('number of public keys cannot be greater than 16')
  }
  if (chunks.length - 3 !== n) {
    throw new Error('incorrect number of public keys found')
  }
  var keys = chunks.slice(1, -2)
  if (!keys.every(isCanonicalPubKey)) {
    throw new Error('non-canonical public key found')
  }
  return {
    nRequiredSigs: m,
    publicKeyBuffers: keys,
    publicKeys: keys.map(function (vchPubKey) {
      return ECPair.fromPublicKeyBuffer(vchPubKey)
    }),
    nPublicKeys: n
  }
}

function isMultisigOutput (script) {
  try {
    parseMultisigScript(script)
    return true
  } catch (e) {
    return false
  }
}

function isNullDataOutput (script) {
  var chunks = decompile(script)
  return chunks[0] === OPS.OP_RETURN
}

function classifyOutput (script) {
  var chunks = decompile(script)

  if (isPubKeyHashOutput(chunks)) {
    return scriptTypes.P2PKH
  } else if (isScriptHashOutput(chunks)) {
    return scriptTypes.P2SH
  } else if (isSegWitPubKeyHashOutput(chunks)) {
    return scriptTypes.P2WPKH
  } else if (isSegWitScriptHashOutput(chunks)) {
    return scriptTypes.P2WSH
  } else if (isMultisigOutput(chunks)) {
    return scriptTypes.MULTISIG
  } else if (isPubKeyOutput(chunks)) {
    return scriptTypes.P2PK
  } else if (isNullDataOutput(chunks)) {
    return scriptTypes.NULLDATA
  }

  return scriptTypes.NONSTANDARD
}

function classifyInput (script, allowIncomplete) {
  var chunks = decompile(script)

  if (isPubKeyHashInput(chunks)) {
    return scriptTypes.P2PKH
  } else if (isMultisigInput(chunks, allowIncomplete)) {
    return scriptTypes.MULTSIG
  } else if (isScriptHashInput(chunks, allowIncomplete)) {
    return scriptTypes.P2SH
  } else if (isPubKeyInput(chunks)) {
    return scriptTypes.P2PK
  }

  return scriptTypes.NONSTANDARD
}

// Standard Script Templates
// {pubKey} OP_CHECKSIG
function pubKeyOutput (pubKey) {
  return compile([pubKey, OPS.OP_CHECKSIG])
}

// OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG
function pubKeyHashOutput (pubKeyHash) {
  typeforce(types.Hash160bit, pubKeyHash)

  return compile([OPS.OP_DUP, OPS.OP_HASH160, pubKeyHash, OPS.OP_EQUALVERIFY, OPS.OP_CHECKSIG])
}

// OP_0 PUSH[{20-byte pubKeyHash}]
function segWitPubKeyHashOutput (pubKeyHash) {
  typeforce(types.Hash160bit, pubKeyHash)

  return compile([OPS.OP_0, pubKeyHash])
}

// OP_0 PUSH[{32-byte scriptHash}}]
function segWitScriptHashOutput (scriptHash) {
  typeforce(types.Hash256bit, scriptHash)

  return compile([OPS.OP_0, scriptHash])
}

// OP_HASH160 {scriptHash} OP_EQUAL
function scriptHashOutput (scriptHash) {
  typeforce(types.Hash160bit, scriptHash)

  return compile([OPS.OP_HASH160, scriptHash, OPS.OP_EQUAL])
}

// m [pubKeys ...] n OP_CHECKMULTISIG
function multisigOutput (m, pubKeys) {
  typeforce(types.tuple(types.Number, [types.Buffer]), arguments)

  var n = pubKeys.length
  if (n < m) throw new Error('Not enough pubKeys provided')

  return compile([].concat(
    OP_INT_BASE + m,
    pubKeys,
    OP_INT_BASE + n,
    OPS.OP_CHECKMULTISIG
  ))
}

// {signature}
function pubKeyInput (signature) {
  typeforce(types.Buffer, signature)

  return compile([signature])
}

// {signature} {pubKey}
function pubKeyHashInput (signature, pubKey) {
  typeforce(types.tuple(types.Buffer, types.Buffer), arguments)

  return compile([signature, pubKey])
}

// <scriptSig> {serialized spkPubKeyHash script}
function scriptHashInput (scriptSig, scriptPubKey) {
  var scriptSigChunks = decompile(scriptSig)
  var serializedScriptPubKey = compile(scriptPubKey)

  return compile([].concat(
    scriptSigChunks,
    serializedScriptPubKey
  ))
}

// OP_0 [signatures ...]
function multisigInput (signatures, scriptPubKey) {
  if (scriptPubKey) {
    try {
      var multisigData = parseMultisigScript(scriptPubKey)
    } catch (e) {
      throw new Error('Expected multisig spkPubKeyHash')
    }

    if (signatures.length < multisigData.nRequiredSigs) throw new Error('Not enough signatures provided')
    if (signatures.length > multisigData.nPublicKeys) throw new Error('Too many signatures provided')
  }

  return compile([].concat(OPS.OP_0, signatures))
}

function nullDataOutput (data) {
  return compile([OPS.OP_RETURN, data])
}

module.exports = {
  compile: compile,
  decompile: decompile,
  fromASM: fromASM,
  toASM: toASM,

  types: scriptTypes,
  number: require('./script_number'),

  isCanonicalPubKey: isCanonicalPubKey,
  isCanonicalSignature: isCanonicalSignature,
  isDefinedHashType: isDefinedHashType,
  isPubKeyHashInput: isPubKeyHashInput,
  isPubKeyHashOutput: isPubKeyHashOutput,
  isSegWitPubKeyHashOutput: isSegWitPubKeyHashOutput,
  isPubKeyInput: isPubKeyInput,
  isPubKeyOutput: isPubKeyOutput,
  isScriptHashInput: isScriptHashInput,
  isScriptHashOutput: isScriptHashOutput,
  isSegWitScriptHashOutput: isSegWitScriptHashOutput,
  isMultisigInput: isMultisigInput,
  isMultisigOutput: isMultisigOutput,
  isNullDataOutput: isNullDataOutput,
  parseMultisigScript: parseMultisigScript,
  classifyOutput: classifyOutput,
  classifyInput: classifyInput,
  pubKeyOutput: pubKeyOutput,
  pubKeyHashOutput: pubKeyHashOutput,
  segWitPubKeyHashOutput: segWitPubKeyHashOutput,
  scriptHashOutput: scriptHashOutput,
  segWitScriptHashOutput: segWitScriptHashOutput,
  multisigOutput: multisigOutput,
  pubKeyInput: pubKeyInput,
  pubKeyHashInput: pubKeyHashInput,
  scriptHashInput: scriptHashInput,
  multisigInput: multisigInput,
  nullDataOutput: nullDataOutput
}

