package crypto

import bifrost.crypto.hash.FastCryptographicHash
import bifrost.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile

import scala.reflect.io.Path
import scala.util.Try
import scorex.crypto.signatures.{Curve25519, SigningFunctions}

object cryptoMain extends cryptoValues with App {

  //SIG algorithm:

  //KG - generation of PK0 and SK0
  println("Generating Key")
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  val exampleKey = KeyFile(password = password, defaultKeyDir = keyFileDir)

  //SIGN - signature generated with SK0
  println("Signing message")
  val exampleSignature = Curve25519.sign(exampleKey.getPrivateKey(password = password).get.privKeyBytes,message)

  //VER - signature verified with PK0
  println("Verify signature")
  assert(Curve25519.verify(exampleSignature,message,exampleKey.pubKeyBytes))

  //FWSIG algorithm:

  //FWKG - generation of PK0 and SK0
  val FWKey = ForwardKeyFile(password,FastCryptographicHash(seed),keyFileDir)
  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t

  //FWUPD - update PK0 and SK0 --> PK0 and SKt where t is in 0 to T

  //FWSIGN - signature generated with SKt

  //FWVER - signature verified with PK0
}

trait cryptoValues {
  val keyFileDir = "/tmp/scorex/test-data/keyfiles/crypto"
  val path: Path = Path(keyFileDir)
  val password = "password"
  val message = "message".getBytes
  val seed = ""
}
