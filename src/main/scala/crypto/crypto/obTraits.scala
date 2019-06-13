package crypto.crypto

import akka.actor.ActorRef
import akka.actor._
import akka.pattern.ask
import akka.util.Timeout

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration._
import scala.language.postfixOps
import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.{MalkinKey, MalkinSignature}
import scorex.crypto.signatures.Curve25519
import scala.math.BigInt

trait obFunctions {
  type Eta = Array[Byte]
  type Sig = Array[Byte]
  type Slot = Int
  type State = Map[String,Double]
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
  type PrivateKey = Array[Byte]
  type Hash = Array[Byte]
  type Pi = Array[Byte]
  type Cert = (PublicKey,Rho,Pi)
  type Block = (Hash,State,Slot,Cert,Rho,Pi,MalkinSignature,PublicKey)
  type Chain = List[Block]
  val confirmationDepth = 10
  val f_s = 0.9
  val forgerReward = 10.0
  val epochLength = 3*confirmationDepth
  val initStakeMax = 100.0

  def uuid: String = java.util.UUID.randomUUID.toString

  /**
    * calculates epoch nonce recursively
    * @param c local chain to be verified
    * @param ep epoch derived from time step
    * @return hash nonce
    */
  def eta(c:Chain,ep:Int): Eta = {
    val t = c.head._3
    println(t)
    if(t==0) {
      //println("eta0")
      //println(bytes2hex(FastCryptographicHash(c.last._5)))
      FastCryptographicHash(c.last._5)
    } else {
      var v: Array[Byte] = Array()
      val epcv = subChain(c,ep*epochLength-epochLength,ep*epochLength-epochLength/3)
      val cnext = subChain(c,0,ep*epochLength-epochLength)
      for(block <- epcv) {
        v = v++block._5
      }
      val eta_ep = FastCryptographicHash(eta(cnext,ep-1)++serialize(ep)++v)
      //println("eta"+ep.toString)
      //println(bytes2hex(eta_ep))
      eta_ep
    }
  }

  /**
    * returns a subchain containing all blocks in a given time interval
    * @param c input chain
    * @param t1 slot lower bound
    * @param t2 slot upper bound
    * @return all blocks in the interval t1 to t2, including blocks of t1 and t2
    */
  def subChain(c:Chain,t1:Int,t2:Int): Chain = {
    var out: Chain = List()
    for (b <- c) {
      if(b._3 <= t2 && b._3 >= t1) {out = out++List(b)}
    }
    out
  }

  /**
    * Aggregate staking function used for calculating threshold per epoch
    * @param a relative stake
    * @param f active slot coefficient
    * @return probability of being elected slot leader
    */
  def phi (a:Double,f:Double): Double = {
    1.0 - scala.math.pow(1.0 - f,a)
  }

  /**
    * Compares the vrf output to the threshold
    * @param y vrf output bytes
    * @param t threshold between 0.0 and 1.0
    * @return true if y mapped to double between 0.0 and 1.0 is less than threshold
    */
  def compare(y: Array[Byte],t: Double):Boolean = {
    var net = 0.0
    var i =0
    for (byte<-y){
      i+=1
      val n = BigInt(byte & 0xff).toDouble
      val norm = scala.math.pow(2.0,8.0*i)
      net += n/norm
    }
    net<t
  }

  /**
    * Gets the relative stake, alpha, of the stakeholder
    * @param party string containing all stakeholders participating in the round
    * @param holderKey stakeholder public key
    * @param chain chain containing stakeholders transactions
    * @return alpha, between 0.0 and 1.0
    */
  def relativeStake(party:String,holderKey:String,chain:Chain): Double = {
    var holderStake = 0.0
    var netStake = 0.0
    for (block<-chain) {
      if (verifyBlock(block)) {
        val (hash, state, slot, cert, y, pi_y, sig, pk) = block
        for (entry <- state) {
          if(verifyTxStamp(entry._1)) {
            if (entry._1.contains(holderKey)) {holderStake+=entry._2; netStake += entry._2}
            if (party.contains(entry._1.take(2*Curve25519.KeyLength))) {netStake += entry._2}
          }
        }
      }
    }
    holderStake/netStake
  }

  /**
    * Verifiable string for communicating between stakeholders
    * @param str data to be diffused
    * @param id holder identification information
    * @param sk_sig holder signature secret key
    * @return string to be diffused
    */
  def diffuse(str: String,id: String,sk_sig: Array[Byte]): String = {
    str+";"+id+";"+bytes2hex(Curve25519.sign(sk_sig,serialize(str+";"+id)))
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    */
  def send(holders:List[ActorRef],command: Any) = {
    for (holder <- holders){
      implicit val timeout = Timeout(2 seconds)
      val future = holder ? command
      val result = Await.result(future, timeout.duration)
      assert(result == "done")
    }
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    * @param input map of holder data
    * @return map of holder data
    */
  def send(holders:List[ActorRef],command: Any,input: Map[String,String]): Map[String,String] = {
    var list:Map[String,String] = input
    for (holder <- holders){
      implicit val timeout = Timeout(2 seconds)
      val future = holder ? command
      Await.result(future, timeout.duration) match {
        case str:String => {
          if (verifyTxStamp(str)) list = list++Map(s"${holder.path}" -> str)
        }
        case _ => println("error")
      }
    }
    list
  }

  /**
    * Sends commands one by one to list of stakeholders, except ref given by holderId
    * @param holderId actor not to send
    * @param holders actor list
    * @param command object to be sent
    */
  def send(holderId:String, holders:List[ActorRef],command: Any) = {
    implicit val timeout = Timeout(2 seconds)
    for (holder <- holders){
      if (s"${holder.path}" != holderId) {
        val future = holder ? command
        val result = Await.result(future, timeout.duration)
        assert(result == "done")
      }
    }
  }

  /**
    * Block verify using key evolving signature
    * @param b input block
    * @returnt true if signature is valid, false otherwise
    */
  def verifyBlock(b:Block): Boolean = {
    val (hash, state, slot, cert, rho, pi, sig, pk) = b
    MalkinKES.verify(pk,hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++rho++pi,sig,slot)
  }

  /**
    * Block verify using key evolving signature and hash rule
    * @param b input block
    * @param c chain with head corresponding to b
    * @return true if signature is valid and b corresponds to c, false otherwise
    */
  def verifyBlock(b:Block,c:Chain): Boolean = {
    val (hash, state, slot, cert, rho, pi, sig, pk) = b
    (FastCryptographicHash(serialize(c.head)).deep == hash.deep
    && MalkinKES.verify(pk,hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++rho++pi,sig,slot))
  }

  /**
    * Verify chain using key evolving siganture and hash rule
    * @param c chain to be verified
    * @return true if chain is valid, false otherwise
    */
  def verifyChain(c:Chain): Boolean = {
    var bool = true
    var i = 0
    bool &&= verifyBlock(c.head)
    for (block <- c.tail ) {
      val block0 = c(i)
      i+=1
      bool &&= (FastCryptographicHash(serialize(block)).deep == block0._1.deep
        && verifyBlock(block))
    }
    bool
  }

  /**
    * Verify diffused strings with public key included in the string
    * @param value string to be checked
    * @return true if signature is valid, false otherwise
    */
  def verifyTxStamp(value: String): Boolean = {
    val values: Array[String] = value.split(";")
    val m = values(0)+";"+values(1)+";"+values(2)+";"+values(3)
    Curve25519.verify(hex2bytes(values(4)),serialize(m),hex2bytes(values(0)))
  }

  /**
    * Byte serialization
    * @param value any object to be serialized
    * @return byte array
    */
  def serialize(value: Any): Array[Byte] = {
    val stream: ByteArrayOutputStream = new ByteArrayOutputStream()
    val oos = new ObjectOutputStream(stream)
    oos.writeObject(value)
    oos.close()
    stream.toByteArray
  }

  /**
    * Deserialize a byte array that was serialized with serialize
    * @param bytes byte array processed with serialize
    * @return original object
    */
  def deserialize(bytes: Array[Byte]): Any = {
    val ois = new ObjectInputStream(new ByteArrayInputStream(bytes))
    val value = ois.readObject
    ois.close()
    value
  }

  def bytes2hex(b: Array[Byte]): String = {
    b.map("%02x" format _).mkString
  }

  def hex2bytes(hex: String): Array[Byte] = {
    if (hex.contains(" ")) {
      hex.split(" ").map(Integer.parseInt(_, 16).toByte)
    } else if (hex.contains("-")) {
      hex.split("-").map(Integer.parseInt(_, 16).toByte)
    } else {
      hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
    }
  }

}
