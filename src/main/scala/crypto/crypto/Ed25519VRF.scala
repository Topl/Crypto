package crypto.Ed25519vrf

import java.security.PublicKey
import java.security.PrivateKey
import java.security.KeyFactory
import java.security.Security
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import bifrost.crypto.hash.FastCryptographicHash
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import crypto.crypto.Ed25519
import scalaz.Alpha
import scorex.crypto.hash.Sha512

import scala.math.BigInt


/**
  * ECVRF-ED25519-SHA512-TAI
  * Elliptic curve Verifiable Random Function based on EdDSA
  * Bouncy Castle implementation of Ed25519 used
  */

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
    * verify an Ed25519 keypair
    * @param sk
    * @param pk
    * @return
    */
  def verifyKeyPair(sk:Array[Byte],pk: Array[Byte]): Boolean = {
    if (pk.length == Ed25519.PUBLIC_KEY_SIZE && sk.length == Ed25519.SECRET_KEY_SIZE) {
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

  /**
    * Validate an untrusted public key
    * @param pk
    * @return true if pk is valid, false otherwise
    */
  def verifyPublicKey(pk: Array[Byte]): Boolean = {
    if (pk.length == Ed25519.PUBLIC_KEY_SIZE) {
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

  /**
    * Random output of VRF routine
    * @param p  input proof, generated from random seed and secret key
    * @return Hash output of proof
    */
  def vrfProofToHash(p: Array[Byte]): Array[Byte] = {
    FastCryptographicHash(p)
  }


  /*
ECVRF Proving
ECVRF_prove(SK, alpha_string)
Input:
SK - VRF private key
alpha_string = input alpha, an octet string
Output:
pi_string - VRF proof, octet string of length ptLen+n+qLen
Steps:
1. Use SK to derive the VRF secret scalar x and the VRF public key Y
= x*B
(this derivation depends on the ciphersuite, as per Section 5.5;
these values can be cached, for example, after key generation,
and need not be rederived each time)
2. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
3. h_string = point_to_string(H)
4. Gamma = x*H
5. k = ECVRF_nonce_generation(SK, h_string)
6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
7. s = (k + c*x) mod q
8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
9. Output pi_string

  */



  def vrfProof(sk: Array[Byte], alpha: Array[Byte]): Array[Byte] = {

    val suite = Array(0x03.toByte)

    def pruneHash(s: Array[Byte]): Array[Byte] = {
      val h: Array[Byte] = Sha512(s).take(32)
      h.update(0,(h(0) & 0xF8).toByte)
      h.update(31,(h(31) & 0x7F).toByte)
      h.update(31,(h(31) | 0x40).toByte)
      h
    }

    def scalarMultBaseEncoded(s: Array[Byte]): Array[Byte] = {
      var r: Array[Byte] = Array.fill(32){0}
      Ed25519.scalarMultBaseEncoded(s,r,0)
      r
    }
    // secret scalar
    val x = pruneHash(sk)
    // public key
    val pk = scalarMultBaseEncoded(x)

    assert(verifyKeyPair(sk,pk))


    /*
    ECVRF_hash_to_try_and_increment(suite_string, Y, alpha_string)
    Input:
    suite_string - a single octet specifying ECVRF ciphersuite.
    Y - public key, an EC point
    alpha_string - value to be hashed, an octet string
    Output:
    H - hashed value, a finite EC point in G
    Steps:
    1. ctr = 0
    2. PK_string = point_to_string(Y)
    3. one_string = 0x01 = int_to_string(1, 1), a single octet with
    value 1
    4. H = "INVALID"
    5. While H is "INVALID" or H is EC point at infinity:
    6.
    A. ctr_string = int_to_string(ctr, 1)
    B. hash_string = Hash(suite_string || one_string || PK_string ||
    alpha_string || ctr_string)
    C. H = arbitrary_string_to_point(hash_string)
    D. If H is not "INVALID" and cofactor > 1, set H = cofactor * H
    E. ctr = ctr + 1
    Output H
     */
    def ECVRF_hash_to_try_and_increment(Y: Array[Byte],a: Array[Byte]): Array[Byte] = {
      var ctr = 0
      val one = Array(0x01.toByte)
      var H: Array[Byte] = Array()
      var Hlogic = false
      while (!Hlogic) {
        val ctr_byte = Array(ctr.toByte)
        H = pruneHash(suite++one++Y++a++ctr_byte)
        ctr += 1
      }
      H
    }


    val m = FastCryptographicHash(alpha)
    var sigma: Array[Byte] = Array.fill(Ed25519.SIGNATURE_SIZE){0}
    Ed25519.sign(
      sk, 0,
      m, 0, m.length,
      sigma, 0
    )
    sigma++m
  }

  def vrfVerify(pk: Array[Byte], p: Array[Byte], b: Array[Byte]): Boolean = {
    val m = p.drop(Ed25519.SIGNATURE_SIZE)
    Ed25519.verify(
      p.take(Ed25519.SIGNATURE_SIZE), 0,
      pk, 0,
      m, 0 , m.length
    ) && b.deep == vrfProofToHash(p).deep
  }

  def byteToBigInt(b: Byte): BigInt = BigInt(b & 0xff)

  def bigIntToBinary(b: BigInt): String = String.format("%8s", b.toString(2) ).replace(' ', '0')


}