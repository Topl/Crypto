package crypto.primitives.eddsa

trait Digest {
  /**
    * return the algorithm name
    *
    * @return the algorithm name
    */
  def getAlgorithmName: String

  /**
    * return the size, in bytes, of the digest produced by this message digest.
    *
    * @return the size, in bytes, of the digest produced by this message digest.
    */
  def getDigestSize: Int

  /**
    * update the message digest with a single byte.
    *
    * @param in the input byte to be entered.
    */
  def update(in: Byte): Unit

  /**
    * update the message digest with a block of bytes.
    *
    * @param in    the byte array containing the data.
    * @param inOff the offset into the byte array where the data starts.
    * @param len   the length of the data.
    */
  def update(in: Array[Byte], inOff: Int, len: Int): Unit

  /**
    * close the digest, producing the final digest value. The doFinal
    * call leaves the digest reset.
    *
    * @param out    the array the digest is to be copied into.
    * @param outOff the offset into the out array the digest is to start at.
    */
  def doFinal(out: Array[Byte], outOff: Int): Int

  /**
    * reset the digest back to it's initial state.
    */
  def reset(): Unit
}

