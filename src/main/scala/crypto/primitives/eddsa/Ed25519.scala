package crypto.primitives.eddsa

import java.security.SecureRandom
import java.util.Arrays

class Ed25519 extends EC {

  def dom2(d: SHA512Digest, phflag: Byte, ctx: Array[Byte]): Unit = {
    if (ctx != null) {
      d.update(DOM2_PREFIX, 0, DOM2_PREFIX.length)
      d.update(phflag)
      d.update(ctx.length.toByte)
      d.update(ctx, 0, ctx.length)
    }
  }

  def generatePrivateKey(random:SecureRandom, k: Array[Byte]): Unit = {
    random.nextBytes(k)
  }

  def generatePublicKey(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int): Unit = {
    val d = createDigest
    val h = new Array[Byte](d.getDigestSize)
    d.update(sk, skOff, SECRET_KEY_SIZE)
    d.doFinal(h, 0)
    val s = new Array[Byte](SCALAR_BYTES)
    pruneScalar(h, 0, s)
    scalarMultBaseEncoded(s, pk, pkOff)
  }

  def implSign(d: SHA512Digest, h: Array[Byte], s: Array[Byte], pk: Array[Byte], pkOff: Int, ctx: Array[Byte], phflag: Byte, m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    dom2(d, phflag, ctx)
    d.update(h, SCALAR_BYTES, SCALAR_BYTES)
    d.update(m, mOff, mLen)
    d.doFinal(h, 0)
    val r = reduceScalar(h)
    val R = new Array[Byte](POINT_BYTES)
    scalarMultBaseEncoded(r, R, 0)
    dom2(d, phflag, ctx)
    d.update(R, 0, POINT_BYTES)
    d.update(pk, pkOff, POINT_BYTES)
    d.update(m, mOff, mLen)
    d.doFinal(h, 0)
    val k = reduceScalar(h)
    val S = calculateS(r, k, s)
    System.arraycopy(R, 0, sig, sigOff, POINT_BYTES)
    System.arraycopy(S, 0, sig, sigOff + POINT_BYTES, SCALAR_BYTES)
  }

  def implSign(sk: Array[Byte], skOff: Int, ctx: Array[Byte], phflag: Byte, m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    if (!checkContextVar(ctx, phflag)) throw new IllegalArgumentException("ctx")
    val d = createDigest
    val h = new Array[Byte](d.getDigestSize)
    d.update(sk, skOff, SECRET_KEY_SIZE)
    d.doFinal(h, 0)
    val s = new Array[Byte](SCALAR_BYTES)
    pruneScalar(h, 0, s)
    val pk = new Array[Byte](POINT_BYTES)
    scalarMultBaseEncoded(s, pk, 0)
    implSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def implSign(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], phflag: Byte, m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    if (!checkContextVar(ctx, phflag)) throw new IllegalArgumentException("ctx")
    val d = createDigest
    val h = new Array[Byte](d.getDigestSize)
    d.update(sk, skOff, SECRET_KEY_SIZE)
    d.doFinal(h, 0)
    val s = new Array[Byte](SCALAR_BYTES)
    pruneScalar(h, 0, s)
    implSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def implVerify(sig: Array[Byte], sigOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], phflag: Byte, m: Array[Byte], mOff: Int, mLen: Int): Boolean = {
    if (!checkContextVar(ctx, phflag)) throw new IllegalArgumentException("ctx")
    val R = Arrays.copyOfRange(sig, sigOff, sigOff + POINT_BYTES)
    val S = Arrays.copyOfRange(sig, sigOff + POINT_BYTES, sigOff + SIGNATURE_SIZE)
    if (!checkPointVar(R)) return false
    if (!checkScalarVar(S)) return false
    val pA = new PointExt
    if (!decodePointVar(pk, pkOff, true, pA)) return false
    val d = createDigest
    val h = new Array[Byte](d.getDigestSize)
    dom2(d, phflag, ctx)
    d.update(R, 0, POINT_BYTES)
    d.update(pk, pkOff, POINT_BYTES)
    d.update(m, mOff, mLen)
    d.doFinal(h, 0)
    val k = reduceScalar(h)
    val nS = new Array[Int](SCALAR_INTS)
    decodeScalar(S, 0, nS)
    val nA = new Array[Int](SCALAR_INTS)
    decodeScalar(k, 0, nA)
    val pR = new PointAccum
    scalarMultStraussVar(nS, nA, pA, pR)
    val check = new Array[Byte](POINT_BYTES)
    encodePoint(pR, check, 0)
    Arrays.equals(check, R)
  }

  def sign(sk: Array[Byte], skOff: Int, m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val ctx = null
    val phflag = 0x00.toByte
    implSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def sign(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int, m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val ctx = null
    val phflag = 0x00.toByte
    implSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def sign(sk: Array[Byte], skOff: Int, ctx: Array[Byte], m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val phflag = 0x00.toByte
    implSign(sk, skOff, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def sign(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], m: Array[Byte], mOff: Int, mLen: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val phflag = 0x00.toByte
    implSign(sk, skOff, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff)
  }

  def signPrehash(sk: Array[Byte], skOff: Int, ctx: Array[Byte], ph: Array[Byte], phOff: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val phflag = 0x01.toByte
    implSign(sk, skOff, ctx, phflag, ph, phOff, PREHASH_SIZE, sig, sigOff)
  }

  def signPrehash(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], ph: Array[Byte], phOff: Int, sig: Array[Byte], sigOff: Int): Unit = {
    val phflag = 0x01.toByte
    implSign(sk, skOff, pk, pkOff, ctx, phflag, ph, phOff, PREHASH_SIZE, sig, sigOff)
  }

  def signPrehash(sk: Array[Byte], skOff: Int, ctx: Array[Byte], ph: SHA512Digest, sig: Array[Byte], sigOff: Int): Unit = {
    val m = new Array[Byte](PREHASH_SIZE)
    if (PREHASH_SIZE != ph.doFinal(m, 0)) throw new IllegalArgumentException("ph")
    val phflag = 0x01.toByte
    implSign(sk, skOff, ctx, phflag, m, 0, m.length, sig, sigOff)
  }

  def signPrehash(sk: Array[Byte], skOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], ph: SHA512Digest, sig: Array[Byte], sigOff: Int): Unit = {
    val m = new Array[Byte](PREHASH_SIZE)
    if (PREHASH_SIZE != ph.doFinal(m, 0)) throw new IllegalArgumentException("ph")
    val phflag = 0x01.toByte
    implSign(sk, skOff, pk, pkOff, ctx, phflag, m, 0, m.length, sig, sigOff)
  }

  def verify(sig: Array[Byte], sigOff: Int, pk: Array[Byte], pkOff: Int, m: Array[Byte], mOff: Int, mLen: Int): Boolean = {
    val ctx = null
    val phflag = 0x00.toByte
    implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen)
  }

  def verify(sig: Array[Byte], sigOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], m: Array[Byte], mOff: Int, mLen: Int): Boolean = {
    val phflag = 0x00.toByte
    implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, mOff, mLen)
  }

  def verifyPrehash(sig: Array[Byte], sigOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], ph: Array[Byte], phOff: Int): Boolean = {
    val phflag = 0x01.toByte
    implVerify(sig, sigOff, pk, pkOff, ctx, phflag, ph, phOff, PREHASH_SIZE)
  }

  def verifyPrehash(sig: Array[Byte], sigOff: Int, pk: Array[Byte], pkOff: Int, ctx: Array[Byte], ph: SHA512Digest): Boolean = {
    val m = new Array[Byte](PREHASH_SIZE)
    if (PREHASH_SIZE != ph.doFinal(m, 0)) throw new IllegalArgumentException("ph")
    val phflag = 0x01.toByte
    implVerify(sig, sigOff, pk, pkOff, ctx, phflag, m, 0, m.length)
  }
}
