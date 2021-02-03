package crypto.primitives.eddsa

import java.security.SecureRandom

class X25519 extends EC {
  val POINT_SIZE = 32
  val SCALAR_SIZE = 32
  val C_A = 486662
  val C_A24:Int = (C_A + 2) / 4

  def calculateAgreement(k: Array[Byte], kOff: Int, u: Array[Byte], uOff: Int, r: Array[Byte], rOff: Int): Boolean = {
    scalarMult(k, kOff, u, uOff, r, rOff)
    !areAllZeroes(r, rOff, POINT_SIZE)
  }

  override def decode32(bs: Array[Byte], off: Int) = {
    var n = bs(off) & 0xFF
    n |= (bs(off+1) & 0xFF) << 8
    n |= (bs(off+2) & 0xFF) << 16
    n |= bs(off+3) << 24
    n
  }

  override def decodeScalar(k: Array[Byte], kOff: Int, n: Array[Int]): Unit = {
    for (i <- 0 until 8) {
      n(i) = decode32(k, kOff + i * 4)
    }
    n(0) &= 0xFFFFFFF8
    n(7) &= 0x7FFFFFFF
    n(7) |= 0x40000000
  }

  def generatePrivateKey(random: SecureRandom, k: Array[Byte]): Unit = {
    random.nextBytes(k)
    k(0) &= 0xF8
    k(SCALAR_SIZE - 1) &= 0x7F
    k(SCALAR_SIZE - 1) |= 0x40
  }

  def generatePublicKey(k: Array[Byte], kOff: Int, r: Array[Byte], rOff: Int): Unit = {
    scalarMultBase(k, kOff, r, rOff)
  }

  private def pointDouble(x: Array[Int], z: Array[Int]): Unit = {
    val A = x25519Field.create
    val B = x25519Field.create
    x25519Field.apm(x, z, A, B)
    x25519Field.sqr(A, A)
    x25519Field.sqr(B, B)
    x25519Field.mul(A, B, x)
    x25519Field.sub(A, B, A)
    x25519Field.mul(A, C_A24, z)
    x25519Field.add(z, B, z)
    x25519Field.mul(z, A, z)
  }

  def scalarMult(k: Array[Byte], kOff: Int, u: Array[Byte], uOff: Int, r: Array[Byte], rOff: Int): Unit = {
    val n = new Array[Int](8)
    decodeScalar(k, kOff, n)
    val x1 = x25519Field.create
    x25519Field.decode(u, uOff, x1)
    val x2 = x25519Field.create
    x25519Field.copy(x1, 0, x2, 0)
    val z2 = x25519Field.create
    z2(0) = 1
    val x3 = x25519Field.create
    x3(0) = 1
    val z3 = x25519Field.create
    val t1 = x25519Field.create
    val t2 = x25519Field.create
    //        assert n[7] >>> 30 == 1;
    var bit = 254
    var swap = 1
    do {
      x25519Field.apm(x3, z3, t1, x3)
      x25519Field.apm(x2, z2, z3, x2)
      x25519Field.mul(t1, x2, t1)
      x25519Field.mul(x3, z3, x3)
      x25519Field.sqr(z3, z3)
      x25519Field.sqr(x2, x2)
      x25519Field.sub(z3, x2, t2)
      x25519Field.mul(t2, C_A24, z2)
      x25519Field.add(z2, x2, z2)
      x25519Field.mul(z2, t2, z2)
      x25519Field.mul(x2, z3, x2)
      x25519Field.apm(t1, x3, x3, z3)
      x25519Field.sqr(x3, x3)
      x25519Field.sqr(z3, z3)
      x25519Field.mul(z3, x1, z3)
      bit -= 1
      val word = bit >>> 5
      val shift = bit & 0x1F
      val kt = (n(word) >>> shift) & 1
      swap ^= kt
      x25519Field.cswap(swap, x2, x3)
      x25519Field.cswap(swap, z2, z3)
      swap = kt
    } while ( {
      bit >= 3
    })
    //        assert swap == 0;
    for (i <- 0 until 3) {
      pointDouble(x2, z2)
    }
    x25519Field.inv(z2, z2)
    x25519Field.mul(x2, z2, x2)
    x25519Field.normalize(x2)
    x25519Field.encode(x2, r, rOff)
  }

  def scalarMultBase(k: Array[Byte], kOff: Int, r: Array[Byte], rOff: Int): Unit = {
    val y = x25519Field.create
    val z = x25519Field.create
    scalarMultBaseYZ(k, kOff, y, z)
    x25519Field.apm(z, y, y, z)
    x25519Field.inv(z, z)
    x25519Field.mul(y, z, y)
    x25519Field.normalize(y)
    x25519Field.encode(y, r, rOff)
  }
}
