package crypto.primitives.mmm

/**
  * AMS 2021:
  * Abstract SIG functionality used in MMM construction
  */

abstract class Sig {
  def generatePublicKey(sk:Array[Byte],skOff:Int,pk:Array[Byte],pkOff:Int):Unit
  def sign(sk:Array[Byte],skOff:Int,m:Array[Byte],mOff:Int,mLen:Int,sig:Array[Byte],sigOff:Int):Unit
  def verify(sig:Array[Byte],sigOff:Int,pk:Array[Byte],pkOff:Int,m:Array[Byte],mOff:Int,mLen:Int):Boolean
}
