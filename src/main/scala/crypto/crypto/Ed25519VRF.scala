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
import crypto.crypto.Ed25519.{PointAccum, PointExt}
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
      var pkext = new Ed25519.PointExt
      val decoded: Boolean = Ed25519.decodePointVar(pk,0,false,pkext)
      if (decoded){
        true
      }else {
        false
      }
    } else {
      false
    }
  }

  /*
   Ed25519 is EdDSA instantiated with:
 +-----------+-------------------------------------------------------+
 | Parameter |                                                 Value |
 +-----------+-------------------------------------------------------+
 |     p     |     p of edwards25519 in [RFC7748] (i.e., 2^255 - 19) |
 |     b     |                                                   256 |
 |  encoding |    255-bit little-endian encoding of {0, 1, ..., p-1} |
 |  of GF(p) |                                                       |
 |    H(x)   |            SHA-512(dom2(phflag,context)||x) [RFC6234] |
 |     c     |       base 2 logarithm of cofactor of edwards25519 in |
 |           |                                   [RFC7748] (i.e., 3) |
 |     n     |                                                   254 |
 |     d     |  d of edwards25519 in [RFC7748] (i.e., -121665/121666 |
 |           | = 370957059346694393431380835087545651895421138798432 |
 |           |                           19016388785533085940283555) |
 |     a     |                                                    -1 |
 |     B     | (X(P),Y(P)) of edwards25519 in [RFC7748] (i.e., (1511 |
 |           | 22213495354007725011514095885315114540126930418572060 |
 |           | 46113283949847762202, 4631683569492647816942839400347 |
 |           |      5163141307993866256225615783033603165251855960)) |
 |     L     |             order of edwards25519 in [RFC7748] (i.e., |
 |           |        2^252+27742317777372353535851937790883648493). |
 |    PH(x)  |                       x (i.e., the identity function) |
 +-----------+-------------------------------------------------------+
 Table 1: Parameters of Ed25519
   */
  def binaryArrayToHex(b: Array[Byte]): String = {
    b.map("%02x" format _).mkString
  }

  val suite: Array[Byte] = Array(0x03.toByte)
  var cofactor: Array[Byte] = Array.fill(Ed25519.SCALAR_BYTES){0x00.toByte}
  var zeroScalar: Array[Byte] = Array.fill(Ed25519.SCALAR_BYTES){0x00.toByte}
  var oneScalar: Array[Byte] = Array.fill(Ed25519.SCALAR_BYTES){0x00.toByte}
  cofactor.update(0,0x08.toByte)
  oneScalar.update(0,0x01.toByte)
  var np: Array[Int] = Array.fill(Ed25519.SCALAR_INTS){0}
  var nb: Array[Int] = Array.fill(Ed25519.SCALAR_INTS){0}
  assert(Ed25519.checkScalarVar(cofactor))
  assert(Ed25519.checkScalarVar(zeroScalar))

  def pruneHash(s: Array[Byte]): Array[Byte] = {
    val h: Array[Byte] = Sha512(s).take(32)
    h.update(0,(h(0) & 0xF8).toByte)
    h.update(31,(h(31) & 0x7F).toByte)
    h.update(31,(h(31) | 0x40).toByte)
    h
  }

  def scalarMultBaseEncoded(s: Array[Byte]): Array[Byte] = {
    var r: Array[Byte] = Array.fill(32){0x00}
    Ed25519.scalarMultBaseEncoded(s,r,0)
    r
  }

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
  def ECVRF_hash_to_try_and_increment(Y: Array[Byte],a: Array[Byte]): (PointAccum, Array[Byte]) = {
    var ctr = 0
    val one = Array(0x01.toByte)
    var hash: Array[Byte] = Array()
    var H = new PointExt
    var HR = new PointAccum
    var Hlogic = false
    while (!Hlogic) {
      val ctr_byte = Array(ctr.toByte)
      hash = Sha512(suite++one++Y++a++ctr_byte).take(Ed25519.POINT_BYTES)
      Hlogic = Ed25519.decodePointVar(hash,0,false,H)
      if (Hlogic){
        Hlogic != Ed25519.isNeutralPoint(H)
      }
      ctr += 1
    }
    Ed25519.decodeScalar(cofactor,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,H,HR)
    (HR, hash)
  }


  /*
    ECVRF_hash_points(P1, P2, ..., PM)
    Input:
    P1...PM - EC points in G
    Output:
    c - hash value, integer between 0 and 2^(8n)-1
    Steps:
    1. two_string = 0x02 = int_to_string(2, 1), a single octet with
    value 2
    2. Initialize str = suite_string || two_string
    3. for PJ in [P1, P2, ... PM]:
    str = str || point_to_string(PJ)
    4. c_string = Hash(str)
    5. truncated_c_string = c_string[0]...c_string[n-1]
    6. c = string_to_int(truncated_c_string)
    7. Output c
  */
  def ECVRF_hash_points(p1: PointAccum, p2: PointAccum, p3: PointAccum, p4: PointAccum): Array[Byte] ={
    val two: Array[Byte] = Array(0x02.toByte)
    var str: Array[Byte] = suite++two
    var r: Array[Byte] = Array.fill(Ed25519.POINT_BYTES){0x00.toByte}
    Ed25519.encodePoint(p1,r,0)
    str = str++r
    Ed25519.encodePoint(p2,r,0)
    str = str++r
    Ed25519.encodePoint(p3,r,0)
    str = str++r
    Ed25519.encodePoint(p4,r,0)
    str = str++r
    Sha512(str).take(16)++Array.fill(Ed25519.SCALAR_BYTES-16){0x00.toByte}
  }


  /*
  ECVRF_nonce_generation_RFC8032(SK, h_string)
  Input:
  SK - an ECVRF secret key
  h_string - an octet string
  Output:
  k - an integer between 0 and q-1
  Steps:
  1. hashed_sk_string = Hash (SK)
  2. truncated_hashed_sk_string =
  hashed_sk_string[32]...hashed_sk_string[63]
  3. k_string = Hash(truncated_hashed_sk_string || h_string)
  4. k = string_to_int(k_string) mod q
  */

  def ECVRF_nonce_generation_RFC8032(sk: Array[Byte],h: Array[Byte]): Array[Byte] = {
    val trunc_hashed_sk = Sha512(sk).drop(32)
    val k_string = Sha512(trunc_hashed_sk++h)
    Ed25519.reduceScalar(k_string)
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
    // secret scalar
    val x = pruneHash(sk)
    // public key
    val pk = scalarMultBaseEncoded(x)
    assert(verifyKeyPair(sk,pk))
    val H: (PointAccum, Array[Byte]) = ECVRF_hash_to_try_and_increment(pk,alpha)
    val nonce = ECVRF_nonce_generation_RFC8032(sk,H._2)
    assert(Ed25519.checkScalarVar(nonce))
    val gamma = new PointAccum
    Ed25519.decodeScalar(x,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,Ed25519.pointCopy(H._1),gamma)
    val k = ECVRF_nonce_generation_RFC8032(sk,H._2)
    assert(Ed25519.checkScalarVar(k))
    val kB = new PointAccum
    val kH = new PointAccum
    Ed25519.scalarMultBase(k,kB)
    Ed25519.decodeScalar(k,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,Ed25519.pointCopy(H._1),kH)
    val c = ECVRF_hash_points(H._1,gamma,kB,kH)
    val s = Ed25519.calculateS(k,c,x)
    var gamma_str: Array[Byte] = Array.fill(Ed25519.POINT_BYTES){0x00.toByte}
    Ed25519.encodePoint(gamma,gamma_str,0)
    val pi = gamma_str++c.take(16)++s
    assert(pi.length == 32+16+32)
    pi
  }

  /*
  ECVRF_verify(Y, pi_string, alpha_string)
  Input:
  Y - public key, an EC point
  pi_string - VRF proof, octet string of length ptLen+n+qLen
  alpha_string - VRF input, octet string
  Output:
  ("VALID", beta_string), where beta_string is the VRF hash output,
  octet string of length hLen; or
  "INVALID"
  Steps:
  1. D = ECVRF_decode_proof(pi_string)
  2. If D is "INVALID", output "INVALID" and stop
  3. (Gamma, c, s) = D
  4. H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
  5. U = s*B - c*Y
  6. V = s*H - c*Gamma
  7. c’ = ECVRF_hash_points(H, Gamma, U, V)
  8. If c and c’ are equal, output ("VALID",
  ECVRF_proof_to_hash(pi_string)); else output "INVALID"
  */


  def vrfVerify(pk: Array[Byte], alpha: Array[Byte], pi: Array[Byte]): Boolean = {
    val gamma_str = pi.take(32)
    val c = pi.slice(32,32+16)++Array.fill(Ed25519.SCALAR_BYTES-16){0x00.toByte}
    val s = pi.drop(32+16)
    assert(Ed25519.checkPointVar(gamma_str))
    assert(Ed25519.checkScalarVar(c))
    assert(Ed25519.checkScalarVar(s))
    val H: (PointAccum, Array[Byte]) = ECVRF_hash_to_try_and_increment(pk,alpha)
    var gamma = new PointExt
    var Y = new PointExt
    Ed25519.decodePointVar(gamma_str,0,false,gamma)
    Ed25519.decodePointVar(pk,0,false,Y)
    var A = new PointAccum //s*B
    var B = new PointAccum //c*Y
    var C = new PointAccum //s*H
    var D = new PointAccum //c*Gamma
    var U = new PointAccum
    var V = new PointAccum
    var g = new PointAccum
    var t = new PointExt
    Ed25519.scalarMultBase(s,A)
    Ed25519.decodeScalar(c,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,Y,B)
    Ed25519.decodeScalar(s,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,Ed25519.pointCopy(H._1),C)
    Ed25519.decodeScalar(c,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,gamma,D)
    Ed25519.decodeScalar(oneScalar,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.pointAddVar(true,Ed25519.pointCopy(A),Ed25519.pointCopy(B),t)
    Ed25519.scalarMultStraussVar(nb,np,t,U)
    Ed25519.pointAddVar(true,Ed25519.pointCopy(C),Ed25519.pointCopy(D),t)
    Ed25519.scalarMultStraussVar(nb,np,t,V)
    Ed25519.scalarMultStraussVar(nb,np,gamma,g)
    val cp = ECVRF_hash_points(H._1,g,U,V)
    c.deep == cp.deep
  }

  /**
    * Random output of VRF routine
    * @param p  input proof, generated from random seed and secret key
    * @return Hash output of proof
    */


  /*
  ECVRF_proof_to_hash(pi_string)
  Input:
  pi_string - VRF proof, octet string of length ptLen+n+qLen
  Output:
  "INVALID", or
  beta_string - VRF hash output, octet string of length hLen
  Important note:
  ECVRF_proof_to_hash should be run only on pi_string that is known
  to have been produced by ECVRF_prove, or from within ECVRF_verify
  as specified in Section 5.3.
  Steps:
  1. D = ECVRF_decode_proof(pi_string)
  2. If D is "INVALID", output "INVALID" and stop
  3. (Gamma, c, s) = D
  4. three_string = 0x03 = int_to_string(3, 1), a single octet with
  value 3
  5. beta_string = Hash(suite_string || three_string ||
  point_to_string(cofactor * Gamma))
  6. Output beta_string
   */

  def vrfProofToHash(pi: Array[Byte]): Array[Byte] = {
    val gamma_str = pi.take(32)
    val c = pi.slice(32,32+16)++Array.fill(Ed25519.SCALAR_BYTES-16){0x00.toByte}
    val s = pi.drop(32+16)
    val three = Array(0x03.toByte)
    assert(Ed25519.checkPointVar(gamma_str))
    assert(Ed25519.checkScalarVar(c))
    assert(Ed25519.checkScalarVar(s))
    val gamma = new PointExt
    val cg = new PointAccum
    Ed25519.decodePointVar(gamma_str,0,false,gamma)
    Ed25519.decodeScalar(cofactor,0,np)
    Ed25519.decodeScalar(zeroScalar,0,nb)
    Ed25519.scalarMultStraussVar(nb,np,gamma,cg)
    var cg_enc = Array.fill(Ed25519.POINT_BYTES){0x00.toByte}
    Ed25519.encodePoint(cg,cg_enc,0)
    Sha512(suite++three++cg_enc)
  }


}