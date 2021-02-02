package crypto

import crypto.box.Curve25519XSalsa20Poly1305._
import crypto.Utils._

object Box {

  def randomNonce() = {
    val nonce = new Array[Byte](nonceBytes)
    random.nextBytes(nonce)
    nonce
  }

}

case class Box(publicKey: Array[Byte], privateKey: Array[Byte]) {

  checkLength(publicKey, publicKeyBytes)
  checkLength(privateKey, secretKeyBytes)

  def encrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](zeroBytes) ++ message
    cryptoBox(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(boxZeroBytes)
  }

  def decrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](boxZeroBytes) ++ message
    cryptoBoxOpen(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(zeroBytes)
  }

}
