package crypto.crypto.malkinKES

import java.security.SecureRandom

import bifrost.crypto.hash.FastCryptographicHash
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import scorex.crypto.hash.Sha512


object MalkinKES {

  val seedBytes = 32
  val pkBytes = Ed25519.PUBLIC_KEY_SIZE
  val skBytes = Ed25519.SECRET_KEY_SIZE

  def SHA1PRNG_secureRandom(seed: Array[Byte]):SecureRandom = {
    //This algorithm uses SHA-1 as the foundation of the PRNG. It computes the SHA-1 hash over a true-random seed value
    // concatenated with a 64-bit counter which is incremented by 1 for each operation.
    // From the 160-bit SHA-1 output, only 64 bits are used.
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    rnd
  }

  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t
  def PRNG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val r1 = FastCryptographicHash(k)
    val r2 = FastCryptographicHash(Sha512(r1++k))
    (r1,r2)
  }

  /**
    * Generate a random keypair for Ed25519
    * @return
    */
  def sKeypair: (Array[Byte],Array[Byte]) = {
    val kpg = new Ed25519KeyPairGenerator
    kpg.init(new Ed25519KeyGenerationParameters(new SecureRandom()))
    val kp = kpg.generateKeyPair
    val sk = kp.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters].getEncoded
    val pk = kp.getPublic.asInstanceOf[Ed25519PublicKeyParameters].getEncoded
    (pk,sk)
  }

  /**
    * Generate a keypair from seed for Ed25519
    * @param seed
    * @return
    */
  def sKeypair(seed: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val kpg = new Ed25519KeyPairGenerator
    kpg.init(new Ed25519KeyGenerationParameters(SHA1PRNG_secureRandom(seed)))
    val kp = kpg.generateKeyPair
    val sk = kp.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters].getEncoded
    val pk = kp.getPublic.asInstanceOf[Ed25519PublicKeyParameters].getEncoded
    (pk,sk)
  }

  def sKeypairFast(seed: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val sk = FastCryptographicHash(seed)
    var pk = Array.fill(32){0x00.toByte}
    Ed25519.generatePublicKey(sk,0,pk,0)
    (pk,sk)
  }

  def sPublic(seed: Array[Byte]): Array[Byte] = {sKeypairFast(seed)._1}

  def sPrivate(seed: Array[Byte]): Array[Byte] = {sKeypairFast(seed)._2}

  def sumKeyGen(seed: Array[Byte],l: Int): (Array[Byte],Array[Byte]) = {
    if(l==0) {
      val r = PRNG(seed)
      val kp1 = sKeypairFast(r._1)
      val pk1 = kp1._1
      val sk1 = kp1._2
      val pk2 = sPublic(r._2)
      val pk = FastCryptographicHash(kp1._1++pk2)
      (pk,sk1++r._2++pk1++pk2)
    } else {
      val r = PRNG(seed)
      val kp1 = sumKeyGen(r._1,l-1)
      val pk1 = kp1._1
      val sk1 = kp1._2
      val pk2 = sPublic(r._2)
      val pk = FastCryptographicHash(kp1._1++pk2)
      (pk,sk1++r._2++pk1++pk2)
    }
  }

  def sumUpdate(t: Int, l: Int, sk: Array[Byte]): Array[Byte] = {
    if (t+1<l/2) {
      sumUpdate(t,l/2,sk)
    } else {
      if (t+1 == l/2) {
        val r = sk.slice(skBytes,skBytes+seedBytes)
        val pk = sk.slice(skBytes+seedBytes+pkBytes,skBytes+seedBytes+2*pkBytes)
        val skp = sPrivate(r)
        var pkp = Array.fill(32){0x00.toByte}
        Ed25519.generatePublicKey(skp,0,pkp,0)
        assert(pk.deep == pkp.deep)
        sPrivate(r)++sk.drop(skBytes+seedBytes+2*pkBytes)
      } else {
        sumUpdate(t-l/2,l/2,sk)
      }
    }
  }

  def sumSign(t:Int,l:Int,sk: Array[Byte],m: Array[Byte]): Array[Byte] = {

    val skp = sk.take(sk.length-seedBytes-2*pkBytes)
    println(l)
    println(skp.length.toString)
    if (l==0) {
      Array(0x00.toByte)
    } else if(t<l/2) {
      if (skp.length == skBytes+seedBytes+2*pkBytes) {
        var sig = Array.fill(Ed25519.SIGNATURE_SIZE){0x00.toByte}
        Ed25519.sign(sk.take(skBytes),0,sk.drop(sk.length-pkBytes),0,m,0,m.length,sig,0)
        sig
      } else {
        sumSign(t, l/2, skp, m)
      }
    } else {
      sumSign(t-l/2, l/2, skp, m)
    }
  }

  def sumVerify = {}

}
