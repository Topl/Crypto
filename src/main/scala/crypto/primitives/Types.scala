package crypto.primitives

import java.security.MessageDigest

/**
  * AMS 2020:
  * Types and hash functions for quickly hashing different data types
  */

trait Types extends SimpleTypes {
  val fch:Fch

  def Sha512(bytes: Array[Byte]):Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-512")
    digest.update(bytes)
    digest.digest()
  }
}

object Types extends SimpleTypes {
  val fch = new Fch
}