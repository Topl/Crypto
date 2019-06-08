package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props}
import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.MalkinSignature
import scorex.crypto.signatures.Curve25519
import crypto.crypto.obFunctions
import scala.math.BigInt

object StakeHolder {
  def props: Props = Props(new StakeHolder)
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}

case object Diffuse
case object Inbox
case object Update
case object UpdateChain
case class Update(t:Int)
case class Populate(n:Int)
case class GenBlock(b: Any)
case class GetBlock(b: Any)
case object Status

class Coordinator extends Actor
  with obFunctions {
  var holders: List[ActorRef] = List()
  val eta0 = FastCryptographicHash(uuid)
  var t = 0
  def receive: Receive = {
    case value: Populate => {
      holders = List.fill(value.n){
        context.actorOf(StakeHolder.props, "holder:" + uuid)
      }
      send(holders,holders)
      val state: State = holders.map{ case ref:ActorRef => s"${ref.path}" -> 1.0}.toMap
      val genBlock:Block = (FastCryptographicHash(serialize(state)++eta0), state, t, (Array(),Array(),Array()), eta0, Array(), (Array(),Array(),Array()))
      send(holders,GenBlock(genBlock))
    }
    case Inbox => send(holders,Inbox)
    case Diffuse => send(holders,Diffuse);send(holders,UpdateChain)
    case Update => {t+=1; send(holders,Update(t))}
    case Status => send(holders,Status)
    case _ => println("received unknown message")
  }
}

class StakeHolder extends Actor
  with obFunctions {
  var inbox:String = ""
  var holderData: String = ""
  var holders: List[ActorRef] = List()
  var diffuseSent = false
  val holderId = s"${self.path}"
  var stake = 0.0
  var t = 0
  val seed = FastCryptographicHash(uuid)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey = MalkinKES.generateKey(seed)
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)

  var localChain:Chain = List()
  var genBlock: Any = 0
  var roundBlock: Any = 0
  var foreignBlock: Any = 0
  var adverseRound = false
  val f_s = 0.99
  var eta = Array(0x00.toByte)

  holderData = bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes)

  def receive: Receive = {
    case value: Update => {
      inbox = ""
      roundBlock = 0
      foreignBlock = 0
      diffuseSent = false
      adverseRound = false
      t = value.t
      malkinKey = MalkinKES.updateKey(malkinKey,t)
      sender() ! "done"
    }
    case Diffuse => {
      if (!diffuseSent) {
        diffuseSent = true
        if (slotLeader) roundBlock = forgeBlock
        for (holder <- holders) {
          if (s"${holder.path}" != holderId) {
            holder ! diffuse(holderData,holderId)
            holder ! GetBlock(roundBlock)
          }
        }
      }
      sender() ! "done"
    }
    case value: GetBlock =>{
      value.b match {
        case b: Block => {
          if (verifyBlock(b,localChain) && foreignBlock == 0 && roundBlock == 0) {
            foreignBlock = b
          } else {
            adverseRound = true
          }
        }
      }
    }
    case UpdateChain => {
      if (!adverseRound && foreignBlock == 0) {
        roundBlock match {
          case 0 => adverseRound = true
          case b:Block => localChain++=List(b);stake+=1.0
        }
      }
      if (!adverseRound && roundBlock == 0){
        foreignBlock match {
          case 0 => adverseRound = true
          case b:Block => localChain++=List(b)
        }
      }
    }
    case value: String => {
      if(verifyTxStamp(value)) inbox = inbox+value+"\n"
    }
    case list: List[ActorRef] => {
      holders = list
      sender() ! "done"
    }
    case gb: GenBlock =>  {
      genBlock = gb.b
      genBlock match {case b:Block => localChain++=List(b)}
      sender() ! "done"
    }
    case Inbox => println(inbox); sender() ! "done"
    case Status => {println(holderId+" t="+t.toString+" s="+stake.toString);sender() ! "done"}
    case _ => println("received unknown message");sender() ! "error"
  }

  def diffuse(str: String,id: String): String = {
    str+";"+id+";"+bytes2hex(Curve25519.sign(sk_sig,serialize(str+";"+id)))
  }

  def slotLeader: Boolean = {
    def phi (a:Double,f:Double): Double = {
      1.0 - scala.math.pow(1.0 - f,a)
    }
    val slot = t
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val alpha = relativeStake
    val threshold = phi(alpha,f_s)
    def convert(y: Array[Byte]):Double = {
      var sum = 0.0
      var i = 0
      for (byte<-y){
        val n = BigInt(byte & 0xff)
        sum+=exp(i)*n.toDouble
        i+=1
      }
      sum/exp(i)
    }
    convert(y)<threshold
  }

  def forgeBlock: Block = {
    val slot:Slot = t
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = FastCryptographicHash(serialize(localChain.head))
    val state:State = Map(diffuse(holderData,holderId)-> 0.01)
    val cert:Cert = (pk_vrf,rho,pi)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++y++pi_y, t)
    (hash,state,slot,cert,y,pi_y,sig)
  }

  def relativeStake: Double = {
    0.1
  }

}
