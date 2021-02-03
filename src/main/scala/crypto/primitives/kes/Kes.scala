package crypto.primitives.kes

import crypto.primitives.mmm
import crypto.primitives.eddsa.Ed25519
import crypto.primitives.B2b256

/**
  * AMS 2021:
  * Key evolving scheme instantiated with Ed25519 and b2b256 fast cryptographic hash using MMM construction
  */

class Sig extends mmm.Sig {
  val ec = new Ed25519
  override def generatePublicKey(sk:Array[Byte],skOff:Int,pk:Array[Byte],pkOff: Int):Unit =
    ec.generatePublicKey(sk:Array[Byte],skOff:Int,pk:Array[Byte],pkOff: Int)

  override def sign(sk:Array[Byte],skOff:Int,m:Array[Byte],mOff:Int,mLen:Int,sig:Array[Byte],sigOff:Int):Unit =
    ec.sign(sk:Array[Byte],skOff:Int,m:Array[Byte],mOff:Int,mLen:Int,sig:Array[Byte],sigOff:Int)

  override def verify(sig:Array[Byte],sigOff:Int,pk:Array[Byte],pkOff:Int,m:Array[Byte],mOff:Int,mLen:Int):Boolean =
    ec.verify(sig:Array[Byte],sigOff:Int,pk:Array[Byte],pkOff:Int,m:Array[Byte],mOff:Int,mLen:Int)
}

class Fch extends mmm.Fch {
  val b2b = new B2b256
  override def hash(input: Array[Byte]): Array[Byte] = {
    b2b.hash(input)
  }
}

class Kes extends mmm.MMM {
  override val fch: mmm.Fch = new Fch
  override val sig: mmm.Sig = new Sig
  override val seedBytes: Int = 32
  override val pkBytes: Int = 32
  override val skBytes: Int = 32
  override val sigBytes: Int = 64
  override val hashBytes: Int = 32
}
