package crypto.Ed25519vrf

import java.math.BigInteger
import java.security.PublicKey
import java.security.PrivateKey
import java.security.KeyFactory
import java.security.Security
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.ECGenParameterSpec

import javax.crypto.KeyAgreement
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.math.ec.ECPoint

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed25519ctxSigner
import org.bouncycastle.crypto.signers.Ed25519phSigner
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.util.encoders.Hex

//case class Ed25519VRF (var pubKeyBytes: Array[Byte],
//                       var secretKeyBytes: Array[Byte],
//                       var proofBytes: Array[Byte],
//                       var seedBytes: Array[Byte],
//                       var outputBytes: Array[Byte]
//                      ) {
//
//}

object Ed25519VRF {

  def uuid: String = java.util.UUID.randomUUID.toString

  /**
    * Generate a random keypair for Ed25519
    * @return
    */
  def vrfKeypair: (Array[Byte],Array[Byte]) = {
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
  def vrfKeypair(seed: Array[Byte]): (Array[Byte],Array[Byte]) = {
    //This algorithm uses SHA-1 as the foundation of the PRNG. It computes the SHA-1 hash over a true-random seed value
    // concatenated with a 64-bit counter which is incremented by 1 for each operation.
    // From the 160-bit SHA-1 output, only 64 bits are used.
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    val kpg = new Ed25519KeyPairGenerator
    kpg.init(new Ed25519KeyGenerationParameters(rnd))
    val kp = kpg.generateKeyPair
    val sk = kp.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters].getEncoded
    val pk = kp.getPublic.asInstanceOf[Ed25519PublicKeyParameters].getEncoded
    (pk,sk)
  }

  /**
    * Generate a random keypair for Elliptic Curve DSA
    * @return
    */
  def ECDSAKeypair: (PublicKey,PrivateKey) = {
    Security.addProvider(new BouncyCastleProvider())
    val ecP = CustomNamedCurves.getByName("curve25519")
    val kpgen: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA","BC")
    kpgen.initialize(EC5Util.convertToSpec(ecP), new SecureRandom())
    val pair: KeyPair = kpgen.generateKeyPair()
    val fact: KeyFactory  = KeyFactory.getInstance("ECDSA", "BC")
    val pk: PublicKey = fact.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()))
    val sk: PrivateKey = fact.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()))
    println("Public Key Format: "+pk.getFormat)
    println("Private Key Format: "+sk.getFormat)
    (pk,sk)
  }

  /**
    * Generate a keypair from seed for Elliptic Curve DSA
    * @param seed
    * @return
    */
  def ECDSAKeypair(seed: Array[Byte]): (PublicKey,PrivateKey) = {
    Security.addProvider(new BouncyCastleProvider())
    //This algorithm uses SHA-1 as the foundation of the PRNG. It computes the SHA-1 hash over a true-random seed value
    // concatenated with a 64-bit counter which is incremented by 1 for each operation.
    // From the 160-bit SHA-1 output, only 64 bits are used.
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    val ecP = CustomNamedCurves.getByName("curve25519")
    val kpgen: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA","BC")
    kpgen.initialize(EC5Util.convertToSpec(ecP), rnd)
    val pair: KeyPair = kpgen.generateKeyPair()
    val fact: KeyFactory  = KeyFactory.getInstance("ECDSA", "BC")
    val pk: PublicKey = fact.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()))
    val sk: PrivateKey = fact.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()))
    println("Public Key Format: "+pk.getFormat)
    println("Private Key Format: "+sk.getFormat)

    (pk,sk)
  }

  /**
    * Validate an untrusted public key
    * @param pk
    * @return true if pk is valid, false otherwise
    */
  def verifyKeyPair(sk:Array[Byte],pk: Array[Byte]): Boolean = {
    if (pk.length == Ed25519PublicKeyParameters.KEY_SIZE && sk.length == Ed25519PrivateKeyParameters.KEY_SIZE) {
      var pkt: Array[Byte] = Array.fill[Byte](Ed25519.PUBLIC_KEY_SIZE)(0)
      Ed25519.generatePublicKey(sk,0,pkt,0)
      if (pkt.deep == pk.deep){
        true
      }else {
        false
      }
    } else {
      false
    }
  }

  def verifyPublicKey(pk: Array[Byte]): Boolean = {
    if (pk.length == Ed25519PublicKeyParameters.KEY_SIZE) {
      var pkt: Array[Byte] = Array.fill[Byte](Ed25519.PUBLIC_KEY_SIZE)(0)

      if (pkt.deep == pk.deep){
        true
      }else {
        false
      }
    } else {
      false
    }
  }

}