package crypto.cryptomain

import bifrost.crypto.hash.FastCryptographicHash
import crypto.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile
import scorex.crypto.signatures.SigningFunctions.Signature

import scala.util.Try
import scorex.crypto.signatures.{Curve25519, Curve25519VRF}
import crypto.forwardsignatures.forwardSignatures
import crypto.forwardtypes.forwardTypes._

object cryptoMain extends forwardSignatures with App {

  //Verifiable Random Function (VRF) scheme using Curve25519

  //Non-Secure naive first attempt
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  println("  Generating Key...")
  val vrfKey: KeyFile = KeyFile(password,seed,keyFileDir)

  def vrfProofToHash(p: Array[Byte]): Array[Byte] = {
    FastCryptographicHash(p)
  }

  def vrfProof(key: KeyFile, password: String, s: Array[Byte]): Array[Byte] = {
    Curve25519VRF.sign(
      key.getPrivateKey(password = password).get.privKeyBytes,
      FastCryptographicHash(s)
    )++FastCryptographicHash(s)
  }

  def vrfVerify(key: KeyFile, p: Array[Byte], b: Array[Byte]): Boolean = {
    Curve25519VRF.verify(
      p.take(Curve25519VRF.SignatureLength),
      p.drop(Curve25519VRF.SignatureLength),
      key.pubKeyBytes
    ) && b.deep == vrfProofToHash(p).deep
  }

  val proof = vrfProof(vrfKey,password,seed)

  val vrfOutput = vrfProofToHash(proof)
  println("  Verify VRF...")
  assert(vrfVerify(vrfKey,proof,vrfOutput))

  println("  Fvrf: \n  "+binaryArrayToHex(vrfOutput)+"\n  ")
  println("  Proof: \n  "+binaryArrayToHex(proof.take(Curve25519VRF.SignatureLength))+"\n  "+binaryArrayToHex(proof.drop(Curve25519VRF.SignatureLength))+"\n  ")
  println("  Signature 1: \n  "+binaryArrayToHex(Curve25519VRF.sign(vrfKey.getPrivateKey(password = password).get.privKeyBytes, FastCryptographicHash(seed)))+"\n  ")
  println("  Signature 2: \n  "+binaryArrayToHex(Curve25519VRF.sign(vrfKey.getPrivateKey(password = password).get.privKeyBytes, FastCryptographicHash(seed)))+"\n  ")






  if (false) {
    //SIG algorithm:
    println("\nOld Signing Algorithm:")
    //KG - generation of PK0 and SK0
    Try(path.deleteRecursively())
    Try(path.createDirectory())
    println("  Generating Key...")
    val exampleKey: KeyFile = KeyFile(password = password, seed = seed, defaultKeyDir = keyFileDir)

    //SIGN - signature generated with SK0
    println("  Signing message...")
    val exampleSignature: Signature = Curve25519.sign(exampleKey.getPrivateKey(password = password).get.privKeyBytes, message)

    //VER - signature verified with PK0
    println("  Verify signature...")
    assert(Curve25519.verify(exampleSignature, message, exampleKey.pubKeyBytes))

    println("\nForward Signing Algorithm:")

    //FWKG - generation of PK0 and SK0
    println("  Generating Forward KeyFile")
    val forwardKey: ForwardKeyFile = ForwardKeyFile(password = password, seed = seed, tMax = T, defaultKeyDir = keyFileDir)

    println("  Signing Message with SK0")
    val exampleSignature0: Signature = Curve25519.sign(forwardKey.getPrivateKey(password).get.privKeyBytes, message)

    println("  Verify Signature made with SK0, indicating KeyFile is at state 0")
    assert(Curve25519.verify(exampleSignature0, message, forwardKey.pubKeyBytes))
    println("    " + Try(Curve25519.verify(exampleSignature0, message, forwardKey.pubKeyBytes)))

    increment(forwardKey, inc1)

    println("  Making Forward Signature 1")
    val forwardSignature1: ForwardSig = forwardSignature(forwardKey, password, message)

    increment(forwardKey, inc2)

    println("  Making Forward Signature 2")
    val forwardSignature2: ForwardSig = forwardSignature(forwardKey, password, message)

    increment(forwardKey, inc3)

    println("  Verify Signature made with SK0 with the current evolved Public Key PKt (should fail)")
    println("    " + Try(Curve25519.verify(exampleSignature0, message, forwardKey.pubKeyBytes)))

    println("  Verify Signature made with SK0 with Base Public Key PK0 (should succeed)")
    println("    " + Try(Curve25519.verify(exampleSignature0, message, forwardKey.basePubKeyBytes)))

    println("  Attempting to forge false signature...")
    val forwardSignature3: ForwardSig =
      (forwardKey.certificates(5), Curve25519.sign(forwardKey.getPrivateKey(password).get.privKeyBytes, message), 5)

    println("  Verifying Forward Signature 1")
    assert(forwardVerify(forwardKey.basePubKeyBytes, message, forwardSignature1))
    println("    " + Try(forwardVerify(forwardKey.basePubKeyBytes, message, forwardSignature1)))

    println("  Verifying Forward Signature 2")
    assert(forwardVerify(forwardKey.basePubKeyBytes, message, forwardSignature2))
    println("    " + Try(forwardVerify(forwardKey.basePubKeyBytes, message, forwardSignature2)))

    println("  Verify false Signature 3 (should fail)")
    println("    " + Try(forwardVerify(forwardKey.basePubKeyBytes, message, forwardSignature3)))
  }

}
