package crypto.primitives.kes

import java.security.SecureRandom

import org.scalatest.FunSuite

class KesTest extends FunSuite {

  test ("MMM Test") {
    val rnd: SecureRandom = new SecureRandom()
    val kes:Kes = new Kes
    val fch:Fch = new Fch

    var t = 0
    var message = rnd.generateSeed(512)
    //println("MMM construction sum composition")
    val logl = 7
    val l = scala.math.pow(2, logl).toInt
    //println(l.toString + " time steps")
    t = 0
    val seed1 = rnd.generateSeed(32)
    val seed2 = rnd.generateSeed(32)
    var sk = kes.sumGenerateKey(seed1, logl)
    var sk2 = kes.sumGenerateKey(seed2, logl)
    var pk = kes.sumGetPublicKey(sk)
    var pk2 = kes.sumGetPublicKey(sk2)
    //println("tree: " + sk)
    //println("Target Private Key Length:")
    //println(kes.skBytes * logl + 2 * kes.pkBytes + 3 * kes.hashBytes * logl)
    //println("Tree Byte Length:")
    var data: Array[Byte] = Array()
    for (item <- sk.toSeq) {
      data = data ++ item
    }
    //println(data.length)
    //println("Private Key Time Step:")
    //println(kes.sumGetKeyTimeStep(sk))
    //println("Verifying key pair<-------------------------------")
    assert(kes.sumVerifyKeyPair(sk, pk))
    //println("Private Key Update:")
    t += (l * 3) / 4 + 1
    sk = kes.sumUpdate(sk, t)
    //println("Key t: " + kes.sumGetKeyTimeStep(sk).toString)
    //println("t: " + t.toString)
    //println("Tree height: " + sk.height.toString)
    //println("Verifying key pair<-------------------------------")
    pk = kes.sumGetPublicKey(sk)
    assert(kes.sumVerifyKeyPair(sk, pk))
    assert(!kes.sumVerifyKeyPair(sk2, pk))
    assert(!kes.sumVerifyKeyPair(sk, pk2))
    assert(kes.sumVerifyKeyPair(sk2, pk2))
    var sig1 = kes.sumSign(sk, message, t)
    assert(kes.sumVerify(pk, message, sig1))
    t += 1
    sk = kes.sumUpdate(sk, t)
    var sig2 = kes.sumSign(sk, message, t)
    sig1 = kes.sumSign(sk, message, t)
    assert(kes.sumVerify(pk, message, sig2))
    assert(kes.sumVerify(pk, message, sig1))
    t = 0
    //println("Testing MMM product composition")
    var prodKey = kes.generateKey(seed1)
    val prodPk = kes.publicKey(prodKey)
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("t: " + t.toString)
    t += 1
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("t: " + t.toString)
    //println("product sign")
    var sigProd = kes.sign(prodKey, message)
    //println("product verify")
    assert(kes.verify(prodPk, message, sigProd,t))

    t += 1
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)

    sigProd = kes.sign(prodKey, message)
    //println("product verify")
    assert(kes.verify(prodPk, message, sigProd,t))

    t += 2
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)

    t += 104
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)
    t += 1000
    //println("Product key time step:")
    //println(kes.getKeyTimeStep(prodKey))
    //println("Updating MMM product key")
    prodKey = kes.updateKey(prodKey, t)

    sigProd = kes.sign(prodKey, message)
    //println("product verify")
    assert(kes.verify(prodPk, message, sigProd,t))
    //println("Product key time step: " + kes.getKeyTimeStep(prodKey).toString)
    //println("t: " + t.toString)

    data = Array()
    for (item <- prodKey._1.toSeq) {
      data = data ++ item
    }
    for (item <- prodKey._2.toSeq) {
      data = data ++ item
    }
    data = data ++ prodKey._3 ++ prodKey._4 ++ prodKey._5
    //println("Key byte legnth: " + data.length.toString)
  }

}
