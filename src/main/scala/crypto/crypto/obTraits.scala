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

  def uuid: String = java.util.UUID.randomUUID.toString

  def send(holders:List[ActorRef],command: Any) = {
    for (holder <- holders){
      implicit val timeout = Timeout(2 seconds)
      val future = holder ? command
      val result = Await.result(future, timeout.duration)
      assert(result == "done")
    }
  }

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

  def verifyBlock(b:Block): Boolean = {
    val (hash, state, slot, cert, y, pi_y, sig, pk) = b
    MalkinKES.verify(pk,hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++y++pi_y,sig,slot)
  }

  def verifyBlock(b:Block,c:Chain): Boolean = {
    val (hash, state, slot, cert, y, pi_y, sig, pk) = b
    (FastCryptographicHash(serialize(c.head)).deep == hash.deep
    && MalkinKES.verify(pk,hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++y++pi_y,sig,slot))
  }

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

  def verifyTxStamp(value: String): Boolean = {
    val values: Array[String] = value.split(";")
    val m = values(0)+";"+values(1)+";"+values(2)+";"+values(3)
    Curve25519.verify(hex2bytes(values(4)),serialize(m),hex2bytes(values(0)))
  }

  def serialize(value: Any): Array[Byte] = {
    val stream: ByteArrayOutputStream = new ByteArrayOutputStream()
    val oos = new ObjectOutputStream(stream)
    oos.writeObject(value)
    oos.close()
    stream.toByteArray
  }

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

  def exp(n: Int): Int = {
    scala.math.pow(2,n).toInt
  }
}
