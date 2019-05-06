package crypto.cryptomain

import bifrost.crypto.hash.FastCryptographicHash
import scorex.crypto.hash.Sha512
import crypto.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile
import crypto.Ed25519vrf.Ed25519VRF
import scorex.crypto.signatures.SigningFunctions.Signature

import scala.util.Try
import scorex.crypto.signatures.{Curve25519, Curve25519VRF}
import crypto.forwardsignatures.forwardSignatures
import crypto.forwardtypes.forwardTypes._
import crypto.forwardkeygen.ForwardKeyFile.uuid
import crypto.crypto.Ed25519

import scala.math.BigInt

object cryptoMain extends forwardSignatures with App {

  //Verifiable Random Function (VRF) scheme using Ed25519
  val (pk, sk) = Ed25519VRF.vrfKeypair(seed)
  println("Private Key")
  println(binaryArrayToHex(sk))
  println("Public Key")
  println(binaryArrayToHex(pk))

  assert(Ed25519VRF.verifyKeyPair(sk,pk))

  //In EdDSA the private key is 256-bit random data
  //Public key is generated in the following



  //Non-Secure first attempt


  var proof: Array[Byte] = Array()
  proof = Ed25519VRF.vrfProof(sk,FastCryptographicHash(uuid))

  var vrfOutput: Array[Byte] = Array()
  vrfOutput = Ed25519VRF.vrfProofToHash(proof)

  assert(Ed25519VRF.vrfVerify(pk,proof,vrfOutput))

//  val numIterate = 100000
//  var bin: Array[Int] = Array.fill(Ed25519.SIGNATURE_SIZE)(0)
//  for (i <- 1 to numIterate) {
//    val oldsig: Array[Byte] = proof.take(Ed25519.SIGNATURE_SIZE)
//    proof = vrfProof(sk,FastCryptographicHash(uuid))
//    val newsig: Array[Byte] = proof.take(Ed25519.SIGNATURE_SIZE)
//    vrfOutput = vrfProofToHash(proof)
//    assert(vrfVerify(pk,proof,vrfOutput))
//    //Bitwise exclusive-or of signatures to detect differences
//    val diff: Array[BigInt] = (oldsig.map(byteToBigInt(_)), newsig.map(byteToBigInt(_))).zipped.map(_^_)
//    for (j <- 0 to Ed25519.SIGNATURE_SIZE-1) {
//      val bit = bigIntToBinary(diff(j/8))(j%8).toString.toInt
//      if (bit == 1) {
//        bin(j) += 0
//      } else {
//        bin(j) += 1
//      }
//    }
//  }
//
  println("  VRF: \n  "+binaryArrayToHex(vrfOutput)+"\n  ")
  println("  Proof: \n  "+binaryArrayToHex(proof.take(Ed25519.SIGNATURE_SIZE))+"\n  "+binaryArrayToHex(proof.drop(Ed25519.SIGNATURE_SIZE))+"\n  ")
//  println("  Diff histogram of successive signatures after "+numIterate+" iterations (Close to 0 = good... Maybe?): ")
//  for (i <- 0 until Curve25519VRF.SignatureLength){
//    print(bin(i)-numIterate/2)
//    print(", ")
//  }
//  print("\n")

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
