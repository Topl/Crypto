package spec.mmm

import bifrost.crypto.hash.FastCryptographicHash
import crypto.crypto.malkinKES.MalkinKES
import org.scalatest._

class MMMSpec extends FlatSpec {
  def uuid: String = java.util.UUID.randomUUID.toString
  var t = 0
  var message = FastCryptographicHash(uuid)
  println("MMM construction sum composition")
  val logl = 7
  val l = scala.math.pow(2, logl).toInt
  println(l.toString + " time steps")
  t = 0
  val seed1 = FastCryptographicHash(uuid)
  val seed2 = FastCryptographicHash(uuid)
  var sk = MalkinKES.sumGenerateKey(seed1, logl)
  var sk2 = MalkinKES.sumGenerateKey(seed2, logl)
  var pk = MalkinKES.sumGetPublicKey(sk)
  var pk2 = MalkinKES.sumGetPublicKey(sk2)
  println("tree: " + sk)
  println("Target Private Key Length:")
  println(MalkinKES.skBytes * logl + 2 * MalkinKES.pkBytes + 3 * MalkinKES.hashBytes * logl)
  println("Tree Byte Length:")
  var data: Array[Byte] = Array()
  for (item <- sk.toSeq) {
    data = data ++ item
  }
  println(data.length)
  println("Private Key Time Step:")
  println(MalkinKES.sumGetKeyTimeStep(sk))
  println("Verifying key pair<-------------------------------")
  assert(MalkinKES.sumVerifyKeyPair(sk, pk))
  println("Private Key Update:")
  t += (l * 3) / 4 + 1
  sk = MalkinKES.sumUpdate(sk, t)
  println("Key t: " + MalkinKES.sumGetKeyTimeStep(sk).toString)
  println("t: " + t.toString)
  println("Tree height: " + sk.height.toString)
  println("Verifying key pair<-------------------------------")
  pk = MalkinKES.sumGetPublicKey(sk)
  assert(MalkinKES.sumVerifyKeyPair(sk, pk))
  assert(!MalkinKES.sumVerifyKeyPair(sk2, pk))
  assert(!MalkinKES.sumVerifyKeyPair(sk, pk2))
  assert(MalkinKES.sumVerifyKeyPair(sk2, pk2))
  var sig1 = MalkinKES.sumSign(sk, message, t)
  assert(MalkinKES.sumVerify(pk, message, sig1))
  t += 1
  sk = MalkinKES.sumUpdate(sk, t)
  var sig2 = MalkinKES.sumSign(sk, message, t)
  sig1 = MalkinKES.sumSign(sk, message, t)
  assert(MalkinKES.sumVerify(pk, message, sig2))
  assert(MalkinKES.sumVerify(pk, message, sig1))
  t = 0
  println("Testing MMM product composition")
  var prodKey = MalkinKES.generateKey(seed1)
  val prodPk = MalkinKES.publicKey(prodKey)
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("t: " + t.toString)
  t += 1
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("t: " + t.toString)
  println("product sign")
  var sigProd = MalkinKES.sign(prodKey, message)
  println("product verify")
  assert(MalkinKES.verify(prodPk, message, sigProd,t))

  t += 1
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)

  sigProd = MalkinKES.sign(prodKey, message)
  println("product verify")
  assert(MalkinKES.verify(prodPk, message, sigProd,t))

  t += 2
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)

  t += 104
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)
  t += 1000
  println("Product key time step:")
  println(MalkinKES.getKeyTimeStep(prodKey))
  println("Updating MMM product key")
  prodKey = MalkinKES.updateKey(prodKey, t)

  sigProd = MalkinKES.sign(prodKey, message)
  println("product verify")
  assert(MalkinKES.verify(prodPk, message, sigProd,t))
  println("Product key time step: " + MalkinKES.getKeyTimeStep(prodKey).toString)
  println("t: " + t.toString)

  data = Array()
  for (item <- prodKey._1.toSeq) {
    data = data ++ item
  }
  for (item <- prodKey._2.toSeq) {
    data = data ++ item
  }
  data = data ++ prodKey._3 ++ prodKey._4 ++ prodKey._5
  println("Key byte legnth: " + data.length.toString)
}
