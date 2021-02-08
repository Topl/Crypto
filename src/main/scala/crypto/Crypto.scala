package crypto

import crypto.primitives.{Ed25519Debug, eddsa}
import scorex.util.encode.{Base16, Base58}

import java.security.SecureRandom
import scala.util.{Failure, Success, Try}

class Crypto {
  println("Topl Crypto Performance Testbed")

  def prnt(tag:String,input:Array[Byte]):Unit = {
    println(tag+": "+Base16.encode(input))
  }
  val numTrials = 10000
  if (true) {
    val RANDOM = new SecureRandom(Array(1L.toByte))
    Ed25519Debug.precompute()
    val t0 = System.nanoTime()
    for( _ <- 1 to numTrials) {
      val sk = new Array[Byte](Ed25519Debug.SECRET_KEY_SIZE)
      val pk = new Array[Byte](Ed25519Debug.PUBLIC_KEY_SIZE)
      val m = new Array[Byte](255)
      val sig1 = new Array[Byte](Ed25519Debug.SIGNATURE_SIZE)
      RANDOM.nextBytes(m)
      RANDOM.nextBytes(sk)
      //prnt("sk",sk)
      Ed25519Debug.generatePublicKey(sk, 0, pk, 0)
      //prnt("pk",pk)
      val mLen = RANDOM.nextInt & 255
      //prnt("m",m)
      Ed25519Debug.sign(sk, 0, m, 0, mLen, sig1, 0)
      //prnt("sig1",sig1)
      val shouldVerify = Ed25519Debug.verify(sig1, 0, pk, 0, m, 0, mLen)
      assert(shouldVerify)
    }
    val t1 = System.nanoTime()
    val outTime = (t1 - t0)*1.0e-9
    val tString = "%6.6f".format(outTime)
    println("Elapsed time Java code: " + tString +"s")
  }
  //println("---------------------------------------------------------")
  if (true) {
    val ec = new eddsa.Ed25519
    ec.precompute()
    val RANDOM = new SecureRandom(Array(1L.toByte))
    val t0 = System.nanoTime()
    for( _ <- 1 to numTrials) {
      val sk = new Array[Byte](ec.SECRET_KEY_SIZE)
      val pk = new Array[Byte](ec.PUBLIC_KEY_SIZE)
      val m = new Array[Byte](255)
      val sig1 = new Array[Byte](ec.SIGNATURE_SIZE)
      RANDOM.nextBytes(m)
      RANDOM.nextBytes(sk)
      //prnt("sk",sk)
      ec.generatePublicKey(sk, 0, pk, 0)
      //prnt("pk",pk)
      val mLen = RANDOM.nextInt & 255
      //prnt("m",m)
      ec.sign(sk, 0, m, 0, mLen, sig1, 0)
      //prnt("sig1",sig1)
      val shouldVerify = ec.verify(sig1, 0, pk, 0, m, 0, mLen)
      assert(shouldVerify)
    }
    val t1 = System.nanoTime()
    val outTime = (t1 - t0)*1.0e-9
    val tString = "%6.6f".format(outTime)
    println("Elapsed time Scala code: " + tString +"s")
  }

  if (true) {
    val RANDOM = new SecureRandom(Array(1L.toByte))
    val t0 = System.nanoTime()
    for( _ <- 1 to numTrials) {
      val m = new Array[Byte](255)
      RANDOM.nextBytes(m)
      val keys = nacl.SigningKeyPair()
      val signature = nacl.SigningKey(keys.privateKey).sign(m)
      val shouldVerify = Try{
        nacl.sign.Ed25519.cryptoSignVerifyDetached(signature,m,0,m.length,keys.publicKey)
      } match {case Success(_)=> true ; case Failure(_) => false}
      assert(shouldVerify)
    }
    val t1 = System.nanoTime()
    val outTime = (t1 - t0)*1.0e-9
    val tString = "%6.6f".format(outTime)
    println("Elapsed time Scala Nacl4s code: " + tString +"s")
  }

}

object Crypto extends App {
  new Crypto
}