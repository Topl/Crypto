package crypto.nacl

import crypto.nacl.Utils._
import crypto.nacl.box.Curve25519XSalsa20Poly1305._
import crypto.nacl.scalarmult.Curve25519

object KeyPair {

  def apply(): KeyPair = {
    val privateKey = new Array[Byte](secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    cryptoBoxKeypair(publicKey, privateKey)
    KeyPair(privateKey, publicKey)
  }

  def apply(privateKey: Array[Byte]): KeyPair = {
    checkLength(privateKey, secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    Curve25519.cryptoScalarmultBase(publicKey, privateKey)
    KeyPair(privateKey, publicKey)
  }

}

case class KeyPair(privateKey: Array[Byte], publicKey: Array[Byte]) {
  checkLength(privateKey, secretKeyBytes)
  checkLength(publicKey, publicKeyBytes)
}
