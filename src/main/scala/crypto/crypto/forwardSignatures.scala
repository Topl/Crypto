package bifrost.forwardsignatures

import bifrost.crypto.hash.FastCryptographicHash
import bifrost.forwardkeygen.ForwardKeyFile
import bifrost.forwardkeygen.ForwardKeyFile.uuid
import scorex.crypto.signatures.Curve25519
import scorex.crypto.signatures.SigningFunctions.Signature

import scala.reflect.io.Path

trait forwardSignatures {
  val keyFileDir = "/tmp/scorex/test-data/keyfiles/crypto"
  val path: Path = Path(keyFileDir)
  val password = "password"
  val message: Array[Byte] = "message".getBytes
  val seed: Array[Byte] = FastCryptographicHash(uuid)
  val T = 24
  val inc1 = 3
  val inc2 = 2
  val inc3 = 5
  var t: Int = 0
  var t0: Int = 0
  var tp: Int = 0

  //FWSIG algorithm:
  type Cert = (Array[Byte],Int,Array[Byte],Signature)
  type ForwardSig = (Cert,Signature,Int)

  //FWVER - signature verified with PK0
  def forwardVerify(PK0: Array[Byte], message: Array[Byte], forwardSig: ForwardSig): Boolean = {
    val cert: Cert = forwardSig._1
    val sig: Signature = forwardSig._2
    val t: Int = forwardSig._3
    val PK0_cert: Array[Byte] = cert._1
    val t_cert: Int = cert._2
    val PKt: Array[Byte] = cert._3
    val sig_cert: Signature = cert._4
    (    Curve25519.verify(sig, message, PKt)
      && PK0.deep == PK0_cert.deep
      && t == t_cert
      && Curve25519.verify(sig_cert, PK0++Array(t.toByte)++PKt, PK0) )
  }

  //FWSIGN - signature generated with SKt
  def forwardSignature(fwk: ForwardKeyFile, password: String, message: Array[Byte]): ForwardSig = {
    (fwk.certificates(fwk.epochNum), Curve25519.sign(fwk.getPrivateKey(password).get.privKeyBytes,message), fwk.epochNum)
  }

  //Key evolution by n number of steps
  def increment(forwardKey: ForwardKeyFile, n:Int): Unit = {
    println("  Evolving Key...")
    t0 = t
    tp = t+n-1
    for (i <- t0 to tp) {
      if (t<T) {
        t = i + 1
        println("    t = " + t.toString)
        forwardKey.forwardUpdate(password)
        forwardKey.saveForwardKeyFile
        assert(t == forwardKey.epochNum)
      }
    }
  }

  def binaryArrayToHex(b: Array[Byte]): String = {
    b.map("%02x" format _).mkString
  }

}
