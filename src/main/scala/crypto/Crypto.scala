package crypto

import crypto.primitives.{Ed25519Debug, eddsa}
import scorex.util.encode.{Base16, Base58}

import java.security.SecureRandom

class Crypto {
  println("Topl Crypto Testbed")

  def prnt(tag:String,input:Array[Byte]):Unit = {
    println(tag+": "+Base16.encode(input))
  }

  if (true) {
    val RANDOM = new SecureRandom(Array(1L.toByte))
    val sk = new Array[Byte](Ed25519Debug.SECRET_KEY_SIZE)
    val pk = new Array[Byte](Ed25519Debug.PUBLIC_KEY_SIZE)
    val m = new Array[Byte](255)
    val sig1 = new Array[Byte](Ed25519Debug.SIGNATURE_SIZE)
    val sig2 = new Array[Byte](Ed25519Debug.SIGNATURE_SIZE)
    RANDOM.nextBytes(m)
    RANDOM.nextBytes(sk)
    prnt("sk",sk)
    Ed25519Debug.generatePublicKey(sk, 0, pk, 0)
    prnt("pk",pk)
    val mLen = RANDOM.nextInt & 255
    prnt("m",m)
    Ed25519Debug.sign(sk, 0, m, 0, mLen, sig1, 0)
    prnt("sig1",sig1)
    Ed25519Debug.sign(sk, 0, pk, 0, m, 0, mLen, sig2, 0)
    prnt("sig2",sig2)
    assert(sig1 sameElements sig2)
    val shouldVerify = Ed25519Debug.verify(sig1, 0, pk, 0, m, 0, mLen)
    assert(shouldVerify)
    sig1(Ed25519Debug.PUBLIC_KEY_SIZE - 1) = (sig1(Ed25519Debug.PUBLIC_KEY_SIZE - 1) ^ 0x80.toByte).toByte
    val shouldNotVerify = Ed25519Debug.verify(sig1, 0, pk, 0, m, 0, mLen)
    assert(!shouldNotVerify)
  }
println("---------------------------------------------------------")
  if (true) {
    val RANDOM = new SecureRandom(Array(1L.toByte))
    val ec = new eddsa.Ed25519
    val sk = new Array[Byte](ec.SECRET_KEY_SIZE)
    val pk = new Array[Byte](ec.PUBLIC_KEY_SIZE)
    val m = new Array[Byte](255)
    val sig1 = new Array[Byte](ec.SIGNATURE_SIZE)
    val sig2 = new Array[Byte](ec.SIGNATURE_SIZE)
    RANDOM.nextBytes(m)
    RANDOM.nextBytes(sk)
    prnt("sk",sk)
    ec.generatePublicKey(sk, 0, pk, 0)
    prnt("pk",pk)
    val mLen = RANDOM.nextInt & 255
    prnt("m",m)
    ec.sign(sk, 0, m, 0, mLen, sig1, 0)
    prnt("sig1",sig1)
    ec.sign(sk, 0, pk, 0, m, 0, mLen, sig2, 0)
    prnt("sig2",sig2)
    assert(sig1 sameElements sig2)
    val shouldVerify = ec.verify(sig1, 0, pk, 0, m, 0, mLen)
    assert(shouldVerify)
    sig1(ec.PUBLIC_KEY_SIZE - 1) = (sig1(ec.PUBLIC_KEY_SIZE - 1) ^ 0x80.toByte).toByte
    val shouldNotVerify = ec.verify(sig1, 0, pk, 0, m, 0, mLen)
    assert(!shouldNotVerify)
  }

}

object Crypto extends App {
  new Crypto
}