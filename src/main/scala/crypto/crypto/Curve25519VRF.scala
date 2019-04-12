package scorex.crypto.signatures

import java.lang.reflect.Constructor

import org.slf4j.LoggerFactory
import org.whispersystems.curve25519.OpportunisticCurve25519Provider
import scorex.crypto.Nat32
import scorex.crypto.hash.{Sha256, Sha512}

import scala.util.{Failure, Try}


object Curve25519VRF extends EllipticCurve[Nat32] {

  import SigningFunctions._

  val SignatureLength25519 = 64
  val KeyLength25519 = 32

  override val SignatureLength = SignatureLength25519
  override val KeyLength = KeyLength25519

  //todo: dirty hack, switch to logic as described in WhisperSystem's Curve25519 tutorial
  //todo: when it'll be possible to pass a random seed from outside
  //todo: https://github.com/WhisperSystems/curve25519-java/pull/7
  private val provider: OpportunisticCurve25519Provider = {
    val constructor = classOf[OpportunisticCurve25519Provider]
      .getDeclaredConstructors
      .head
      .asInstanceOf[Constructor[OpportunisticCurve25519Provider]]
    constructor.setAccessible(true)
    constructor.newInstance()
  }

  override def createKeyPair(seed: Array[Byte]): (PrivateKey, PublicKey) = {
    val hashedSeed = Sha256.hash(seed)
    val privateKey = provider.generatePrivateKey(hashedSeed)
    privateKey -> provider.generatePublicKey(privateKey)
  }

  override def sign(privateKey: PrivateKey, message: MessageToSign): Signature = {
    require(privateKey.length == KeyLength)
    provider.calculateSignature(Sha512.hash(message), privateKey, message)
  }

  override def verify(signature: Signature, message: MessageToSign, publicKey: PublicKey): Boolean = Try {
    require(signature.length == SignatureLength)
    require(publicKey.length == KeyLength)
    provider.verifySignature(publicKey, message, signature)
    true
  }.recoverWith { case e =>
    log.debug("Error while message signature verification", e)
    Failure(e)
  }.getOrElse(false)

  override def createSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret = {
    provider.calculateAgreement(privateKey, publicKey)
  }

  protected lazy val log = LoggerFactory.getLogger(this.getClass)
}