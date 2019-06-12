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
case class SendBlock(b: Any)
case object Status
case object ForgeBlocks
case object GetGenKeys

class Coordinator extends Actor
  with obFunctions {
  var holders: List[ActorRef] = List()
  val eta0 = FastCryptographicHash(uuid)
  val coordId = s"${self.path}"
  var t = 0
  val seed = FastCryptographicHash(uuid)
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey = MalkinKES.generateKey(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)
  val coordData = bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes)
  var genKeys:Map[String,String] = Map()

  def receive: Receive = {
    case value: Populate => {
      holders = List.fill(value.n){
        context.actorOf(StakeHolder.props, "holder:" + uuid)
      }
      send(holders,holders)
      genKeys = send(holders,GetGenKeys,genKeys)
      val genBlock:Block = forgeGenBlock
      send(holders,GenBlock(genBlock))
    }
    case Inbox => send(holders,Inbox)
    case Update => {
      println("t = "+t.toString)
      send(holders,Diffuse)
      send(holders,ForgeBlocks)
      send(holders,UpdateChain)
      t+=1
      send(holders,Update(t))
    }
    case Status => send(holders,Status)
    case _ => println("received unknown message")
  }

  def forgeGenBlock: Block = {
    val slot:Slot = t
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = FastCryptographicHash(seed)
    val r = scala.util.Random
    val state: State = holders.map{ case ref:ActorRef => diffuse(coordData,genKeys(s"${ref.path}").replace(";",":")) -> 100.0 * r.nextDouble}.toMap
    val cert:Cert = (pk_vrf,rho,pi)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++y++pi_y)
    (hash,state,slot,cert,y,pi_y,sig,pk_kes)
  }

  def diffuse(str: String,id: String): String = {
    str+";"+id+";"+bytes2hex(Curve25519.sign(sk_sig,serialize(str+";"+id)))
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
  val f_s = 0.5
  val forgerReward = 1.0
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
        send(holderId,holders,diffuse(holderData,holderId))
        diffuseSent = true
      }
      sender() ! "done"
    }
    case ForgeBlocks => {
      if (diffuseSent) {
        if (slotLeader) roundBlock = forgeBlock
        send(holderId,holders,SendBlock(roundBlock))
      }
      sender() ! "done"
    }
    case value: SendBlock =>{
      value.b match {
        case b: Block => {
          if (verifyBlock(b,localChain) && foreignBlock == 0 && roundBlock == 0) {
            foreignBlock = b
          } else {
            adverseRound = true
          }
        }
        case 0 =>
      }
      sender() ! "done"
    }
    case UpdateChain => {
      if (!adverseRound && foreignBlock == 0) {
        roundBlock match {
          case 0 => adverseRound = true
          case b:Block => localChain = List(b)++localChain
        }
      }
      if (!adverseRound && roundBlock == 0){
        foreignBlock match {
          case 0 => adverseRound = true
          case b:Block => localChain = List(b)++localChain
        }
      }
      sender() ! "done"
    }
    case value: String => {
      if(verifyTxStamp(value)) inbox = inbox+value+"\n"
      sender() ! "done"
    }
    case list: List[ActorRef] => {
      holders = list
      sender() ! "done"
    }
    case gb: GenBlock =>  {
      genBlock = gb.b
      genBlock match {case b:Block => localChain = List(b)++localChain}
      sender() ! "done"
    }
    case Inbox => {println(inbox); sender() ! "done"}
    case Status => {
      println(holderId+" t = "+t.toString+" stake = "+stake.toString+" chain length = "+localChain.length.toString+" valid chain = "+verifyChain(localChain).toString)
      sender() ! "done"
    }
    case GetGenKeys => {sender() ! diffuse(holderData,holderId)}
    case _ => {println("received unknown message");sender() ! "error"}
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
    compare(y,threshold)
  }

  def forgeBlock: Block = {
    val slot:Slot = t
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = FastCryptographicHash(serialize(localChain.head))
    val state:State = Map(diffuse(holderData,holderId)->forgerReward)
    val cert:Cert = (pk_vrf,rho,pi)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++cert._1++cert._2++cert._3++y++pi_y)
    (hash,state,slot,cert,y,pi_y,sig,pk_kes)
  }

  def relativeStake: Double = {
    var holderStake = 0.0
    var netStake = 0.0
    for (block<-localChain) {
      if (verifyBlock(block)) {
        val (hash, state, slot, cert, y, pi_y, sig, pk) = block
        for (entry <- state) {
          if(verifyTxStamp(entry._1)) {
            if (entry._1.contains(bytes2hex(pk_sig))) {holderStake+=entry._2; netStake += entry._2}
            if (inbox.contains(entry._1.take(2*Curve25519.KeyLength))) {netStake += entry._2}
          }
        }
      }
    }
    stake = holderStake
    holderStake/netStake
  }

}
