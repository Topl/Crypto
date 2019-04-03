package crypto

import bifrost.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile
import scorex.crypto.signatures.SigningFunctions.Signature
import scala.util.Try
import scorex.crypto.signatures.Curve25519
import bifrost.forwardsignatures.forwardSignatures
object cryptoMain extends forwardSignatures with App {

  //SIG algorithm:
  println("\nOld Signing Algorithm:")
  //KG - generation of PK0 and SK0
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  println("  Generating Key...")
  val exampleKey: KeyFile = KeyFile(password = password,seed = seed, defaultKeyDir = keyFileDir)

  //SIGN - signature generated with SK0
  println("  Signing message...")
  val exampleSignature: Signature = Curve25519.sign(exampleKey.getPrivateKey(password = password).get.privKeyBytes,message)

  //VER - signature verified with PK0
  println("  Verify signature...")
  assert(Curve25519.verify(exampleSignature,message,exampleKey.pubKeyBytes))


  println("\nForward Signing Algorithm:")

  //FWKG - generation of PK0 and SK0
  println("  Generating Forward KeyFile")
  val forwardKey: ForwardKeyFile = ForwardKeyFile(password = password, seed = seed, tMax = T, defaultKeyDir = keyFileDir)

  println("  Signing Message with SK0")
  val exampleSignature0: Signature = Curve25519.sign(forwardKey.getPrivateKey(password).get.privKeyBytes,message)

  println("  Verify Signature made with SK0, indicating KeyFile is at state 0")
  assert(Curve25519.verify(exampleSignature0,message,forwardKey.pubKeyBytes))
  println("    "+Try(Curve25519.verify(exampleSignature0,message,forwardKey.pubKeyBytes)))

  increment(forwardKey,inc1)

  println("  Making Forward Signature 1")
  val forwardSignature1: ForwardSig = forwardSignature(forwardKey,password,message)

  increment(forwardKey,inc2)

  println("  Making Forward Signature 2")
  val forwardSignature2: ForwardSig = forwardSignature(forwardKey,password,message)

  increment(forwardKey,inc3)

  println("  Verify Signature made with SK0 with the current evolved Public Key PKt (should fail)")
  println("    "+Try(Curve25519.verify(exampleSignature0,message,forwardKey.pubKeyBytes)))

  println("  Verify Signature made with SK0 with Base Public Key PK0 (should succeed)")
  println("    "+Try(Curve25519.verify(exampleSignature0,message,forwardKey.basePubKeyBytes)))

  println("  Attempting to forge false signature...")
  val forwardSignature3: ForwardSig =
    (forwardKey.certificates(5), Curve25519.sign(forwardKey.getPrivateKey(password).get.privKeyBytes,message), 5)

  println("  Verifying Forward Signature 1")
  assert(forwardVerify(forwardKey.basePubKeyBytes,message,forwardSignature1))
  println("    "+Try(forwardVerify(forwardKey.basePubKeyBytes,message,forwardSignature1)))

  println("  Verifying Forward Signature 2")
  assert(forwardVerify(forwardKey.basePubKeyBytes,message,forwardSignature2))
  println("    "+Try(forwardVerify(forwardKey.basePubKeyBytes,message,forwardSignature2)))

  println("  Verify false Signature 3 (should fail)")
  println("    "+Try(forwardVerify(forwardKey.basePubKeyBytes,message,forwardSignature3)))

}


