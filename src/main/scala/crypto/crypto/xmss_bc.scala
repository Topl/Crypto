package crypto.crypto.xmss_bc

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.bc.BCObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.Xof
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.Strings
import org.bouncycastle.util.encoders.Base64


class Xmss_bc {

  def generateKeyPair: (PrivateKey,PublicKey) = {
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastlePQCProvider)
    val kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC")
    kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512))
    val kp = kpg.generateKeyPair
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) != null) Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
    (kp.getPrivate,kp.getPublic)
  }

  def generateKeyPair(seed: Array[Byte]): (PrivateKey,PublicKey) = {
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastlePQCProvider)
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    val kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC")
    kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512),rnd)
    val kp = kpg.generateKeyPair
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) != null) Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
    (kp.getPrivate,kp.getPublic)
  }

  def sign(sk: PrivateKey,msg: Array[Byte]): Array[Byte] = {
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastlePQCProvider)
    val sig = Signature.getInstance("SHA512withXMSS", "BCPQC")
    assert(sig.isInstanceOf[StateAwareSignature])
    val xmssSig = sig.asInstanceOf[StateAwareSignature]
    xmssSig.initSign(sk)
    xmssSig.update(msg, 0, msg.length)
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) != null) Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
    sig.sign
  }

  def verify(pk: PublicKey, msg: Array[Byte], s: Array[Byte]): Boolean = {
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastlePQCProvider)
    val sig = Signature.getInstance("SHA512withXMSS", "BCPQC")
    assert(sig.isInstanceOf[StateAwareSignature])
    val xmssSig = sig.asInstanceOf[StateAwareSignature]
    xmssSig.initVerify(pk)
    xmssSig.update(msg, 0, msg.length)
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) != null) Security.removeProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
    xmssSig.verify(s)
  }

  def updateKey = {}

}
