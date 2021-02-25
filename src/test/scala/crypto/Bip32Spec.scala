package crypto

import org.scalatest.FunSuite
import scodec.bits.HexStringSyntax

class Bip32Spec extends FunSuite {

  test ("Bip32 Test") {
    val m = DeterministicWallet.generate(hex"000102030405060708090a0b0c0d0eee")
    Console.err.println("Generate a master key "+m.sk.toString)
  }

}
