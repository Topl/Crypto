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

  if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastlePQCProvider)

  def generateKeyPair(): KeyPair = {
    val kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC")
    kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512), new SecureRandom())
    kpg.generateKeyPair
  }

  def generateKeyPair(seed: Array[Byte]): KeyPair = {
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    val kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC")
    kpg.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA512), rnd)
    kpg.generateKeyPair
  }

  def sign(kp: KeyPair,msg: Array[Byte]): Array[Byte] = {
    val sig = Signature.getInstance("SHA512withXMSS", "BCPQC")
    assert(sig.isInstanceOf[StateAwareSignature])
    val xmssSig = sig.asInstanceOf[StateAwareSignature]
    xmssSig.initSign(kp.getPrivate)
    xmssSig.update(msg, 0, msg.length)
    sig.sign
  }

  def verify(pk: PublicKey, msg: Array[Byte], s: Array[Byte]): Boolean = {
    val sig = Signature.getInstance("SHA512withXMSS", "BCPQC")
    assert(sig.isInstanceOf[StateAwareSignature])
    val xmssSig = sig.asInstanceOf[StateAwareSignature]
    xmssSig.initVerify(pk)
    xmssSig.update(msg, 0, msg.length)
    xmssSig.verify(s)
  }

  def updateKey = {}

}
