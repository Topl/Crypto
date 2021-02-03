package crypto.primitives.mmm

/**
  * AMS 2021:
  * Abstract Fast Cryptographic Hash for use with MMM
  */

abstract class Fch {
  def hash(input: Array[Byte]): Array[Byte]
}