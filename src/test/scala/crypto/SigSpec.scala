package crypto.primitives

import java.security.SecureRandom

import org.scalatest.FunSuite

class SigSpec extends FunSuite {

  test ("Sig Test") {
    val rnd: SecureRandom = new SecureRandom()
    val s:Sig = new Sig

    var message = rnd.generateSeed(512)

    val seed1 = rnd.generateSeed(32)
    val keys = s.createKeyPair(seed1)
    val sigma = s.sign(keys._1,message)

    val shouldVerify = s.verify(sigma,message,keys._2)
    assert(shouldVerify)

    val badsig = sigma.clone()
    badsig(s.signatureLength - 1) = (badsig(s.signatureLength - 1) ^ 0x80).toByte
    val shouldNotVerify = s.verify(badsig,message,keys._2)
    assert(!shouldNotVerify)
  }

}
