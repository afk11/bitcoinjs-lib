var bscript = require('./script')
var crypto = require('./crypto')
var bufferEquals = require('buffer-equals')
var typeforce = require('typeforce')
var types = require('./types')

var ECPair = require('./ecpair')
var ECSignature = require('./ecsignature')
var Transaction = require('./transaction')

/**
 * Design goals
 *
 *  - tolerate arbitrary sigHashType's on signatures
 *  - given tx, nIn, txOut, we can reliably check a redeemScript and eventual witnessScript at signing
 *  - reliably extract signatures from a signed input
 *  - create, and re-serialize given minimal state
 *  - clear separation of 'standard scripts' and the various script-hash scripts
 *
 * @param tx - the transaction we want to sign
 * @param nIn - the input we will sign here
 * @param txOut - the transaction output containing the value and spkPubKeyHash.
 */
function InSigner (tx, nIn, txOut) {
  if (!tx instanceof Transaction) {
    throw new Error('A transaction is required for InSigner')
  }

  this.tx = tx
  this.nIn = nIn
  this.txOut = txOut

  this.publicKeys = []
  this.signatures = []
  this.requiredSigs = null

  this.extractScriptSig()
}

/**
 * This algorithm attempts to link signatures based on
 * the ordering OP_CHECKMULTISIG would use.
 * This does NOT handle arbitrary linking of sigs<->keys.
 *
 * @param ecsigs - list of signature buffers
 * @param publicKeys - public keys to try and link against
 * @param scriptCode - scriptCode - for verification
 * @param sigVersion - transaction hashing version
 * @returns {Array}
 */
InSigner.prototype.sortMultisigs = function (ecsigs, publicKeys, scriptCode, sigVersion) {
  var results = []
  var hash
  var ikey = 0
  var isig = 0
  var sig, key
  var success = true
  var sigsCount = ecsigs.length
  var keysCount = publicKeys.length
  while (success && ecsigs.length > 0) {
    sig = ECSignature.parseScriptSignature(ecsigs[isig])
    key = publicKeys[ikey]
    hash = this.tx.hashForSignature(this.nIn, scriptCode, sig.hashType, sigVersion === 1, this.txOut.value)
    if (key.verify(hash, sig.signature)) {
      isig++
      results[key.getPublicKeyBuffer().toString('binary')] = ecsigs[isig]
    }
    ikey++
    if (sigsCount > keysCount) {
      success = false
    }
  }

  return results
}

/**
 * Parse a scriptSig, assuming scriptSigs only contain PUSHDATA's.
 *
 * @param scriptSig - the scriptSig to decompile
 * @return {[Buffer]}
 */
var decompileSig = function (scriptSig) {
  var elements = bscript.decompile(scriptSig)
  for (var i = 0; i < elements.length; i++) {
    if (elements[i] instanceof Buffer === false) {
      throw new Error('Unparsable script')
    }
  }
  return elements
}

/**
 * This function is intended only for the BASE_TYPES
 * TODO: remove scriptCode & sigVersion, only required for sorting multisigs
 *
 * @param scriptType - determined scriptType
 * @param data - data from a decompiled scriptSig or witness
 * @param scriptCode - the script code the data is meant to solve
 * @param sigVersion - signature hashing version
 */
InSigner.prototype.extractFromData = function (scriptType, data, scriptCode, sigVersion) {

  var size = data.length
  // When adding a new script type, edit here

  if (scriptType === bscript.types.P2PKH) {
    this.requiredSigs = 1
    if (size === 2) {
      this.signatures = [data[0]]
      this.publicKeys = [ECPair.fromPublicKeyBuffer(data[1])]
    }
  }

  if (scriptType === bscript.types.P2PK) {
    this.requiredSigs = 1
    if (size === 1) {
      this.signatures = [data[0]]
    }
  }

  if (scriptType === bscript.types.MULTISIG) {
    var multisigData = bscript.parseMultisigScript(bscript.decompile(scriptCode))
    this.requiredSigs = multisigData.nRequiredSigs
    this.publicKeys = multisigData.publicKeys

    if (size > 1) {
      var sigs = this.sortMultisigs(data.slice(1, -1), this.publicKeys, scriptCode, sigVersion)
      this.publicKeys.forEach(function (publicKey, idx) {
        var str = publicKey.getPublicKeyBuffer().toString('binary')
        // rely on publicKeys being taken in order provided in redeemScript for idx
        if (sigs[str] !== undefined) {
          this.signatures[idx] = sigs[str]
        }
      })
    }
  }
}

/**
 * A high level function for parsing a signature. (ie, handles P2SH / segwit)
 * Extract signatures / nRequiredSigs / public keys / redeemScript / witnessScript
 * from any representation of the BASE_TYPES
 */
InSigner.prototype.extractScriptSig = function () {

  var scriptType = bscript.classifyOutput(this.txOut.script)
  var scriptSig = this.tx.ins[this.nIn].script

  if ([bscript.types.MULTISIG, bscript.types.P2PK, bscript.types.P2PKH].indexOf(scriptType) !== -1) {
    this.extractFromData(scriptType, decompileSig(scriptSig), this.txOut.script, Transaction.SIG_V0)
  }

  if (scriptType === bscript.types.P2SH) {
    var sigData = decompileSig(scriptSig)
    if (sigData.length > 0) {
      this.redeemScript = sigData[sigData.length - 1]
      scriptType = bscript.classifyOutput(this.redeemScript)
      this.extractFromData(scriptType, sigData.slice(0, -1), this.redeemScript, Transaction.SIG_V0)
    }
  }

  if (scriptType === bscript.types.P2WPKH) {
    this.requiredSigs = 1
    if (typeof this.tx.ins[this.nIn].witness !== 'undefined' && this.tx.ins[this.nIn].witness.length === 2) {
      this.signatures = [this.tx.ins[this.nIn].witness[0]]
      this.publicKeys = [ECPair.fromPublicKeyBuffer(this.tx.ins[this.nIn].witness[1])]
    }
  } else if (scriptType === bscript.types.P2WSH) {
    if (typeof this.tx.ins[this.nIn].witness !== 'undefined' && this.tx.ins[this.nIn].witness.length === 2) {
      var vWit = this.tx.ins[this.nIn].witness
      if (vWit.length > 0) {
        this.witnessScript = vWit[vWit.length - 1]
        var witnessType = bscript.classifyOutput(this.witnessScript)
        this.extractFromData(witnessType, vWit.slice(0, -1), this.witnessScript, Transaction.SIG_V1)
      }
    }
  }
}

/**
 * Helper function to produce a script signature
 *
 * @param key
 * @param scriptCode
 * @param sigHashType
 * @param sigVersion
 * @returns Buffer
 */
InSigner.prototype.calculateSignature = function (key, scriptCode, sigHashType, sigVersion) {
  return key
    .sign(this.tx.hashForSignature(this.nIn, scriptCode, sigHashType, sigVersion === 1, this.txOut.value))
    .toScriptSignature(sigHashType)
}

/**
 * Attempt to 'solve' the given `scriptCode`. Returns an object:
 * {
 *   type: ...,
 *   solvedBy: []
 * }
 *
 * while also saving signatures/pubkeys as state.
 * - For script-hash commitments, `solvedBy` is an array where the
 *   first element is the script-hash (P2SH / P2WSH)
 * - For other script types, `solvedBy` is the list of keys/hashes
 *   the private key should be checked against.
 *
 * @param key - the private key to solve with
 * @param scriptCode - the scriptCode to solve
 * @param sigHashType
 * @param sigVersion - signature hashing version, ie, normal or segwit
 * @returns {{type: *, solvedBy: Array}}
 */
InSigner.prototype.solve = function (key, scriptCode, sigHashType, sigVersion) {

  typeforce(types.Number, sigHashType)
  typeforce(types.Number, sigVersion)

  var outputType = bscript.classifyOutput(scriptCode)
  var decompiled = bscript.decompile(scriptCode)
  var solvedBy = []

  switch (outputType) {
    case bscript.types.NONSTANDARD:
    default:
      throw new Error('Unable to sign a non-standard transaction')

    // We can only determine the relevant hash from these:
    case bscript.types.P2SH:
      solvedBy.push(decompiled[1])
      break
    case bscript.types.P2WSH:
      solvedBy.push(decompiled[1])
      break

    // We can solve signatures for these
    // When adding a new script type, edit here
    case bscript.types.P2PK:
      solvedBy[0] = decompiled[0]
      if (bufferEquals(key.getPublicKeyBuffer(), decompiled[0])) {
        this.signatures[0] = this.calculateSignature(key, scriptCode, sigHashType, sigVersion)
      }

      this.requiredSigs = 1
      break
    case bscript.types.P2PKH:
      solvedBy[0] = decompiled[2]
      if (bufferEquals(crypto.hash160(key.getPublicKeyBuffer()), decompiled[2])) {
        this.signatures[0] = this.calculateSignature(key, scriptCode, sigHashType, sigVersion)
        this.publicKeys[0] = ECPair.fromPublicKeyBuffer(key.getPublicKeyBuffer());
      }

      this.requiredSigs = 1
      break
    case bscript.types.MULTISIG:
      var multisigInfo = bscript.parseMultisigScript(bscript.decompile(scriptCode))
      this.requiredSigs = multisigInfo.nRequiredSigs
      this.publicKeys = multisigInfo.publicKeys

      var myPublicKey = key.getPublicKeyBuffer()
      var thePublicKey;
      var sig;

      for (var i = 0, keyLen = multisigInfo.publicKeyBuffers.length; i < keyLen; i++) {
        thePublicKey = multisigInfo.publicKeyBuffers[i];
        if (bufferEquals(myPublicKey, thePublicKey)) {
          sig = this.calculateSignature(key, scriptCode, sigHashType, sigVersion);
          this.signatures[i] = sig;
        }
      }

      break
    case bscript.types.P2WPKH:
      solvedBy[0] = decompiled[1]
      this.requiredSigs = 1
      if (bufferEquals(key.getPublicKeyBuffer(), decompiled[1])) {
        this.signatures[0] = this.calculateSignature(key, bscript.pubKeyHashOutput(decompiled[1]), sigHashType, Transaction.SIG_V1)
        this.publicKeys[0] = ECPair.fromPublicKeyBuffer(decompiled[1])
      }

      break
  }

  return {
    type: outputType,
    solvedBy: solvedBy
  }
}

/**
 * High level sign function
 * @param key - the private key
 * @param redeemScript - the redeemScript (optional unless UTXO is P2SH)
 * @param witnessScript - the redeemScript (optional unless witness is used)
 * @param sigHashType
 * @returns {boolean}
 */
InSigner.prototype.sign = function (key, redeemScript, witnessScript, sigHashType) {
  var solved, solution
  try {
    // Attempt to solve using against the spkPubKeyHash, sigVersion 0
    solution = this.solve(key, this.txOut.script, sigHashType, Transaction.SIG_V0)
    solved = true
  } catch (e) {
    solved = false
  }

  // If the spkPubKeyHash was solvable, and the type is P2SH, we try again with the redeemScript
  if (solved && solution.type === bscript.types.P2SH) {
    typeforce(types.Buffer, redeemScript)
    if (!bufferEquals(crypto.ripemd160(crypto.sha256(redeemScript)), solution.solvedBy[0])) {
      throw new Error("Incorrect redeem script: hash doesn't match")
    }
    try {
      // solution updated, type is whatever the redeemScript was
      // check it's still solvable, be sure it doesn't have another P2SH
      solution = this.solve(key, redeemScript, sigHashType, Transaction.SIG_V0)
      solved = bscript.types.P2SH !== solution.type
    } catch (e) {
      solved = false
    }
    if (solved) {
      this.redeemScript = redeemScript
    }
  }

  // If the spkPubKeyHash was (still - because of P2SH)
  if (solved) {
    var subSolution
    if (solution.type === bscript.types.P2WPKH) {
      var keyHashScript = bscript.pubKeyHashOutput(solution.solvedBy[0])
      try {
        subSolution = this.solve(key, keyHashScript, sigHashType, Transaction.SIG_V1)
      } catch (e) {
        solved = false
      }
    } else if (solution.type === bscript.types.P2WSH) {
      typeforce(types.Buffer, witnessScript)
      if (!bufferEquals(crypto.sha256(witnessScript), solution.solvedBy[0])) {
        throw new Error("Incorrect witness script: hash doesn't match")
      }
      try {
        subSolution = this.solve(key, witnessScript, sigHashType, Transaction.SIG_V1)
        solved = [bscript.types.P2SH, bscript.types.P2WSH, bscript.types.P2WPKH].indexOf(subSolution.type) === -1
      } catch (e) {
        solved = false
      }
      if (solved) {
        this.witnessScript = witnessScript
      }
    }
  }

  return solved
}

/**
 * Return whether the input is fully signed (so
 * long as the fields are populated correctly)
 *
 * @returns {boolean}
 */
InSigner.prototype.isFullySigned = function () {
  return this.requiredSigs !== 0 && this.requiredSigs === this.signatures.length
}

/**
 * Take a `sigData` and populate the scriptSig given
 * the signatures/keys we know about.
 *
 * @param outputType - output script type
 * @param sigData - object containing `scriptSig` and `witness`
 * @returns {boolean}
 */
InSigner.prototype.serializeStandard = function (outputType, sigData) {
  sigData = sigData || {
    scriptSig: new Buffer(),
    witness: []
  }

  if (this.isFullySigned()) {
    // When adding a new script type, edit here
    switch (outputType) {
      case bscript.types.P2PK:
        sigData.scriptSig = bscript.pubKeyInput(this.signatures[0])
        break
      case bscript.types.P2PKH:
        sigData.scriptSig = bscript.pubKeyHashInput(this.signatures[0], this.publicKeys[0].getPublicKeyBuffer())
        break
      case bscript.types.MULTISIG:
        sigData.scriptSig = bscript.multisigInput(this.signatures.map(function (signature) {
          if (signature instanceof Buffer === false) {
            throw new Error('debugging probably required')
          }
          return signature;
        }))
        break
    }
    return true
  }

  return false
}

/**
 * Serialize an inputs signature data, fully accounting
 * for P2SH / P2WSH
 *
 * @returns {{scriptSig: Buffer, witness: Array}}
 */
InSigner.prototype.serializeSigData = function () {
  var type = bscript.classifyOutput(this.txOut.script)
  var sigData = {
    scriptSig: new Buffer(''),
    witness: []
  }

  var isSerialized = this.serializeStandard(type, sigData)
  var p2sh = false

  if (!isSerialized && type === bscript.types.P2SH) {
    p2sh = true
    type = bscript.classifyOutput(this.redeemScript)
    isSerialized = this.serializeStandard(type, sigData)
  }

  if (!isSerialized && type === bscript.types.P2WPKH) {
    sigData = {
      scriptSig: new Buffer(),
      witness: [this.signatures[0], this.publicKeys[0].getPublicKeyBuffer()]
    }
  } else if (!isSerialized && type === bscript.types.P2WSH) {
    type = bscript.classifyOutput(this.witnessScript)
    isSerialized = this.serializeStandard(type, sigData)
    if (isSerialized) {
      sigData = {
        scriptSig: new Buffer(),
        witness: bscript
          .decompile(sigData.scriptSig)
          .push(this.witnessScript)
      }
    }
  }

  if (p2sh) {
    sigData = {
      scriptSig: bscript
        .decompile(sigData.scriptSig)
        .push(this.redeemScript),
      witness: sigData.witness
    }
  }

  return sigData
}

/**
 * Create a TxSigner for this transaction instance
 * @param tx
 * @constructor
 */
function TxSigner (tx) {
  if (tx === undefined || (tx instanceof Transaction) === false) {
    throw new Error('A transaction is required for TxSigner')
  }

  this.tx = tx.clone()
  this.states = []
}

/**
 * Sign a transaction.
 *
 * @param nIn - the input to sign
 * @param key - the private key to sign with
 * @param txOut - the transaction output referenced in the input (containing value & script)
 * @param redeemScript - the redeemScript is optional, unless called for by the spkPubKeyHash
 * @param witnessScript - the witnessScript is optional, unless called for by the spkPubKeyHash/P2SH script
 * @param sigHashType - SIGHASH type to sign with
 */
TxSigner.prototype.sign = function (nIn, key, txOut, redeemScript, witnessScript, sigHashType) {
  typeforce(types.Number, nIn)
  typeforce(types.Object, txOut)
  typeforce(types.maybe(Buffer), redeemScript)
  typeforce(types.maybe(Buffer), witnessScript)
  typeforce(types.maybe(Number), sigHashType)
  if (sigHashType === undefined) {
    sigHashType = Transaction.SIGHASH_ALL
  }

  if (this.states[nIn] === undefined) {
    this.states[nIn] = new InSigner(this.tx, nIn, txOut)
  }

  if (!this.states[nIn].sign(key, redeemScript, witnessScript, sigHashType)) {
    throw new Error('Unsignable input: ', nIn)
  }

  return true
}

/**
 * Produce a Transaction with our changes.
 */
TxSigner.prototype.done = function () {
  var tx = this.tx.clone()
  var states = this.states
  this.states.forEach(function (state, idx) {
    if (states[idx] !== undefined) {
      var sigData = states[idx].serializeSigData()
      tx.ins[idx].script = sigData.scriptSig
      tx.ins[idx].witness = sigData.witness
    }
  })

  return tx
}

module.exports = TxSigner
