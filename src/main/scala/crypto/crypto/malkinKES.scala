package crypto.crypto

import java.security.SecureRandom

import bifrost.crypto.hash.FastCryptographicHash
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import scorex.crypto.hash.Sha512


class malkinKES {

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
  def kesPRNG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
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

  def sPublic(seed: Array[Byte]): Array[Byte] = {sKeypair(seed)._1}

  def sPrivate(seed: Array[Byte]): Array[Byte] = {sKeypair(seed)._2}

  def keyGen(seed: Array[Byte],l: Int): (Array[Byte],Array[Byte]) = {
    if(l==0) {
      val r = kesPRNG(seed)
      val kp1 = sKeypair(r._1)
      val pk1 = kp1._1
      val sk1 = kp1._2
      val pk2 = sPublic(r._2)
      val pk = Sha512(kp1._1++pk2)
      (pk,sk1++r._2++pk1++pk2)
    } else {
      val r = kesPRNG(seed)
      val kp1 = keyGen(r._1,l-1)
      val pk1 = kp1._1
      val sk1 = kp1._2
      val pk2 = sPublic(r._2)
      val pk = Sha512(kp1._1++pk2)
      (pk,sk1++r._2++pk1++pk2)
    }

  }




}
