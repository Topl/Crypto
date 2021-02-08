package crypto.primitives.rsa

import java.security.{MessageDigest, SecureRandom}
import scala.math.BigInt
import scala.collection.mutable

/**
  * AMS 2021:
  * Proof of concept Scala implementation of RSA accumulator
  * Implemented following https://github.com/westarlabs/rsa-accumulator
  */

class RsaAccumulator {
  val keySize = 3072
  val primeSize: Int = keySize/2
  val accumulatorSize = 128
  val primeCertainty = 5
  val rnd:SecureRandom = new SecureRandom

  class SHA256Digest {
    val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
    def Sha256(bytes: Array[Byte]):Array[Byte] = {
      digest.reset()
      digest.update(bytes)
      digest.digest()
    }
    def getAlgorithmName: String = "SHA-256"
    def getDigestSize: Int = 32
    def update(in: Byte): Unit = digest.update(in)
    def update(in: Array[Byte], inOff: Int, len: Int): Unit = digest.update(in,inOff,len)
    def doFinal(out: Array[Byte], outOff: Int): Int = {
      digest.digest(out,outOff,out.length)
    }
    def reset(): Unit = digest.reset()
  }

  val digest = new SHA256Digest
  val n:BigInt = {
    val (p,q) = twoLargePrimes(primeSize,rnd)
    p*q
  }
  val A0:BigInt = nextBigInteger(BigInt(0),n,rnd)
  var A:BigInt = A0
  val members:mutable.Map[BigInt,BigInt] = mutable.Map.empty

  def size:Int = members.keySet.size

  def nextBigInteger(min:BigInt,max:BigInt,r:SecureRandom): BigInt = {
    assert(min<=max)
    var out:BigInt = BigInt(0)
    val len:Int = if(min.bitLength == max.bitLength) {
      min.bitLength
    } else {
      min.bitLength + rnd.nextInt(max.bitLength-min.bitLength)
    }
    while(out < max || out >= min) {
      out = BigInt(len,r)
    }
    out
  }

  def nextBigInteger(max:BigInt,r:SecureRandom): BigInt = nextBigInteger(BigInt(0),max,r)
  def nextBigInteger(r:SecureRandom): BigInt = nextBigInteger(BigInt(2).pow(256),r)
  def largePrime(len:Int,r:SecureRandom):BigInt = BigInt.probablePrime(len,r)

  def twoLargePrimes(len:Int,r:SecureRandom):(BigInt,BigInt) = {
    val out1 = BigInt.probablePrime(len,r)
    var out2 = BigInt.probablePrime(len,r)
    while (out1 == out2) out2 = BigInt.probablePrime(len,r)
    (out1,out2)
  }

  def hashToPrime(input:BigInt, len:Int = 120, initNonce:BigInt = BigInt(0)):(BigInt,BigInt) = {
    var nonce = initNonce
    var test = hashToLength(input + nonce,len)
    while (!test.isProbablePrime(primeCertainty)) {
      nonce += BigInt(1)
      test = hashToLength(input + nonce,len)
    }
    (test,nonce)
  }

  def hashToLength(input:BigInt,len:Int):BigInt = {
    var str = ""
    val n:Int = Math.ceil(len / 256.00).toInt
    for (i <- 0 to n){
      str += bytesToHex(digest.Sha256((input+BigInt(i)).toString(10).getBytes))
    }
    if (len % 256 > 0) {
      str = str.substring((len % 256) / 4)
    }
    BigInt(str,16)
  }

  def bytesToHex(bytes: Array[Byte]): String = {
    val HEX_ARRAY = "0123456789abcdef".toCharArray
    val hexChars = new Array[Char](bytes.length * 2)
    for (j <- bytes.indices) {
      val v = bytes(j) & 0xFF
      hexChars(j * 2) = HEX_ARRAY(v >>> 4)
      hexChars(j * 2 + 1) = HEX_ARRAY(v & 0x0F)
    }
    new String(hexChars)
  }

  def verifyMembership(A:BigInt,x:BigInt,nonce:BigInt,proof:BigInt,n:BigInt):Boolean = {
    val p = hashToPrime(x,accumulatorSize,nonce)
    proof.modPow(p._1,n) == A
  }

  def add(x:BigInt):BigInt = {
    members.get(x) match {
      case Some(_) => A
      case None =>
        val (hp,nonce) = hashToPrime(x,accumulatorSize,BigInt(0))
        A = A.modPow(hp,n)
        members.update(x,nonce)
        A
    }
  }

  def delete(x:BigInt):BigInt = {
    members.get(x) match {
      case Some(_) =>
        members.remove(x)
        var prod = BigInt(1)
        for ((k,v) <- members) {
          prod *= hashToPrime(k,accumulatorSize,v)._1
        }
        A = A0.modPow(prod,n)
        A
      case None => A
    }
  }

  def prove(x:BigInt):Option[BigInt] = {
    members.get(x) match {
      case Some(_) =>
        var prod = BigInt(1)
        for ((k,v) <- members) {
          if (k != x) {
            prod *= hashToPrime(k,accumulatorSize,v)._1
          }
        }
        Some(A0.modPow(prod,n))
      case None => None
    }
  }

}
