package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props}
import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.{MalkinKey, MalkinSignature}
import scorex.crypto.signatures.Curve25519
import util.control.Breaks._
import scala.util.Random
import java.io.{BufferedWriter, FileWriter}

/**
  * Ouroboros Prosomoiotís:
  *
  * Dynamic proof of stake protocol simulated with akka actors
  * based on Praos and Genesis revisions of Ouroboros
  *
  */


// companion objects for actors
object StakeHolder {
  def props: Props = Props(new StakeHolder)
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}

// case objects and classes for pattern matching messages between actors
case object Diffuse
case object Inbox
case object Update
case object UpdateChain
case object UpdateChainFast
case class Update(t:Int)
case class Populate(n:Int)
case class GenBlock(b: Any)
case class SendBlock(b: Any,s:Array[Byte])
case class SendChain(c: Any,s:String)
case class WriteFile(fw: Any)
case class NewDataFile(name:String)
case object CloseDataFile
case object Status
case object ForgeBlocks
case object GetGenKeys

/**
  * Coordinator actor that initializes the genesis block and instantiates the staking party,
  * sends messages to participants to execute a round
  */
class Coordinator extends Actor
  with obFunctions {
  //empty list of stake holders
  var holders: List[ActorRef] = List()
  //initial nonce for genesis block
  val eta0 = FastCryptographicHash(uuid)
  val coordId = s"${self.path}"
  //slot
  var t = 0
  //set of keys so gensis block can be signed and verified by verifyBlock
  val seed = FastCryptographicHash(uuid)
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey = MalkinKES.generateKey(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)
  val coordData:String = bytes2hex(pk_sig)+":"+bytes2hex(pk_vrf)+":"+bytes2hex(pk_kes)
  val coordKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  //empty list of keys to be populated by stakeholders once they are instantiated
  var genKeys:Map[String,String] = Map()
  var fileWriter:Any = 0

  def receive: Receive = {
    /**populates the holder list with stakeholder actor refs
      * This is the F_init functionality */
    case value: Populate => {
      holders = List.fill(value.n){
        context.actorOf(StakeHolder.props, "holder:" + uuid)
      }
      send(holders,holders)
      genKeys = send(holders,GetGenKeys,genKeys)
      assert(!containsDuplicates(genKeys))
      val genBlock:Block = forgeGenBlock
      send(holders,GenBlock(genBlock))
    }
    /**tells actors to print their inbox */
    case Inbox => send(holders,Inbox)
    /**Execute the round by sending each stakeholder a sequence of commands */
    /**holders list is shuffled to emulate unpredictable ordering of messages */
    case Update => {
      //if (t%epochLength==1) {send(holders,Status)}
      t+=1
      println("t = "+t.toString)
      send(Random.shuffle(holders),Update(t))
      send(Random.shuffle(holders),Diffuse)
      send(Random.shuffle(holders),ForgeBlocks)
      send(Random.shuffle(holders),UpdateChainFast)
      if (dataOutFlag && t%dataOutInterval==0) send(holders,WriteFile(fileWriter))
    }
    //tells actors to print status */
    case Status => {
      send(holders,Status)
    }
    case value:NewDataFile => if(dataOutFlag) {
      fileWriter = new BufferedWriter(new FileWriter(value.name))
      val fileString = (
        "Holder_number"
        + " t"
        + " alpha"
        + " blocks_forged"
        + " chain_length"
        + " chain_hash"
        +"\n"
        )
      fileWriter match {
        case fw: BufferedWriter => fw.write(fileString)
        case _ => println("error: file writer not initialized")
      }
    }
    case CloseDataFile => if(dataOutFlag) {
      fileWriter match {
        case fw:BufferedWriter => fw.close()
        case _ => println("error: file writer close on non writer object")
      }
    }
    case _ => println("received unknown message")
  }
  /**creates genesis block to be sent to all stakeholders */
  def forgeGenBlock: Block = {
    val slot:Slot = t
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = eta0
    val r = scala.util.Random
    // set initial stake distribution, set to random value between 0.0 and initStakeMax for each stakeholder
    val state: State = holders.map{ case ref:ActorRef => signTx(
      genesisBytes
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(0))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(1))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(2)),
      serialize(coordId),sk_sig,pk_sig) -> BigDecimal(initStakeMax * r.nextDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt}.toMap
    var party: Party = List()
    for (holder <- holders){
      val values = genKeys(s"${holder.path}").split(";")
      party ++= List((hex2bytes(values(0)),hex2bytes(values(1)),hex2bytes(values(2))))
    }
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,party,1.0)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi)
    (hash,state,slot,cert,rho,pi,sig,pk_kes)
  }
}

/**
  * Stakeholder actor that executes the staking protocol and communicates with other stakeholders,
  * sends the coordinator the public key upon instantiation and gets the genesis block from coordinator
  */

class StakeHolder extends Actor
  with obFunctions {
  var inbox:String = ""
  var stakingParty:Party = List()
  var holderData: String = ""
  var holders: List[ActorRef] = List()
  var diffuseSent = false
  val holderId = s"${self.path}"
  var alpha_Ep = 0.0
  var blocksForged = 0
  var t = 0
  val seed = FastCryptographicHash(uuid)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey:MalkinKey = MalkinKES.generateKey(seed)
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)
  var localChain:Chain = List()
  var foreignChains:List[Chain] = List()
  var genBlock: Any = 0
  var genBlockHash: Array[Byte] = Array()
  var roundBlock: Any = 0
  var eta_Ep:Array[Byte] = Array()
  var Tr_Ep: Double = 0.0
  var holderIndex = -1
  var localState:LocalState = Map()
  var stakingState:LocalState = Map()
  var memPool:MemPool = List()
  val publicKeys = (pk_sig,pk_vrf,pk_kes)

  //stakeholder public keys
  holderData = bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes)

  def receive: Receive = {
    /**updates time, the kes key, and resets variables */
    case value: Update => time({
      if (holderIndex == 0 && printFlag) {println("holder "+holderIndex.toString+" Update")}
      inbox = ""
      roundBlock = 0
      diffuseSent = false
      t = value.t
      malkinKey = MalkinKES.updateKey(malkinKey,t)
      sender() ! "done"
    },holderIndex)

    /**sends all other stakeholders the public keys, only happens once per round */
    case Diffuse => {
      if (!diffuseSent) {
        send(holderId,Random.shuffle(holders),diffuse(holderData,holderId,sk_sig))
        diffuseSent = true
      }
      sender() ! "done"
    }

    /**checks eligibility to forge blocks and sends chain to other holders if a new block is forged */
    case ForgeBlocks => time({
      if (holderIndex == 0 && printFlag) {println("holder "+holderIndex.toString+" ForgeBlocks")}
      if (t%epochLength == 1){
        val txString = diffuse(holderData,holderId,sk_sig)
        stakingParty = setParty(txString+"\n"+inbox)
        alpha_Ep = relativeStake(stakingParty,publicKeys,localChain,t)
        if (holderIndex == 0 && printFlag) {
          println("holder "+holderIndex.toString+" alpha = "+alpha_Ep.toString)
          stakingState = updateLocalState(stakingState,subChain(localChain,(t/epochLength)*epochLength-2*epochLength+1,(t/epochLength)*epochLength-epochLength))
          val rs = relativeStake(stakingParty,publicKeys,stakingState)
          println("alpha = "+rs.toString)
          println(alpha_Ep == rs)
          assert(alpha_Ep == rs)
        }
        Tr_Ep = phi(alpha_Ep,f_s)
        eta_Ep = eta(localChain,t/epochLength)
      }
      if (diffuseSent) {
        if (slotLeader) {
          roundBlock = forgeBlock
          if (holderIndex == 0 && printFlag) {println("holder "+holderIndex.toString+" is slot a leader")}
        }
        roundBlock match {
          case b:Block => {
            localChain = List(b)++localChain
            send(holderId,Random.shuffle(holders),SendChain(localChain,diffuse(holderData,holderId,sk_sig)))
            blocksForged+=1
          }
          case _ =>
        }
      }
      sender() ! "done"
    },holderIndex)

    /**receives chains from other holders and stores them */
    case value: SendChain => {
      if (verifyTxStamp(value.s) && inbox.contains(idInfo(value.s))) {
        value.c match {
          case c: Chain => {
            foreignChains = foreignChains ++ List(c)
          }
          case _ => println("error")
        }
      }
      sender() ! "done"
    }

    /**updates local chain if a longer valid chain is detected */
    case UpdateChain => time({
      for (chain <- foreignChains) {
        if (chain.length>localChain.length){
          val trueChain = verifyChain(chain,genBlockHash)
          if(!trueChain) println("error: invalid chain")
          //assert(trueChain)
          if (trueChain) localChain = chain
        }
      }
      foreignChains = List()
      sender() ! "done"
    },holderIndex)
    /**updates local chain if a longer valid chain is detected
      * finds common prefix and only checks new blocks */
    case UpdateChainFast => time({
      if (holderIndex == 0 && printFlag) {println("holder "+holderIndex.toString+" Update Chain")}
      for (chain <- foreignChains) {
        if (chain.length>localChain.length){
          var trueChain = false
          if (localChain.length == 1) {
            if (holderIndex == 0 && printFlag) {println("inheriting chain")}
            trueChain = verifyChain(chain,genBlockHash)
          } else {
            var prefixIndex = 0
            var foundCommonPrefix = false
            breakable {
              for (block <- chain.drop(chain.length-localChain.length)) {
                if (block._1.deep == localChain(prefixIndex)._1.deep) {
                  if (holderIndex == 0 && printFlag) {println("found common prefix at i = "+prefixIndex.toString)}
                  foundCommonPrefix = true
                  trueChain = verifyChain(chain, genBlockHash,prefixIndex)
                  break
                }
                prefixIndex += 1
              }
            }
            if (!foundCommonPrefix) {
              if (holderIndex == 0 && printFlag) {println("no prefix found, checking entire chain")}
              trueChain = verifyChain(chain,genBlockHash)
            }
          }
          if(!trueChain) println("error: invalid chain")
          if (trueChain) localChain = chain
        }
      }
      foreignChains = List()
      sender() ! "done"
    },holderIndex)

    /**validates diffused string from other holders and stores in inbox */
    case value: String => {
      if(verifyTxStamp(value)) inbox = inbox+value+"\n"
      sender() ! "done"
    }

    /**accepts list of other holders from coordinator */
    case list: List[ActorRef] => {
      holders = list
      var i = 0
      for (holder<- holders){
        if (holderId == s"${holder.path}") holderIndex = i
        i+=1
      }
      sender() ! "done"
    }

    /**accepts genesis block from coordinator */
    case gb: GenBlock =>  {
      genBlock = gb.b
      genBlock match {
        case b:Block => {
          localChain = List(b)++localChain
          genBlockHash = FastCryptographicHash(serialize(genBlock))
        }
        case _ => println("error")
      }
      sender() ! "done"
    }

    /**prints inbox */
    case Inbox => {println(inbox); sender() ! "done"}

    /**prints stats */
    case Status => {
      val trueChain = verifyChain(localChain,genBlockHash)
      println(holderId+"\nt = "+t.toString+" alpha = "+alpha_Ep.toString+" blocks forged = "
        +blocksForged.toString+"\n chain length = "+localChain.length.toString+" valid chain = "
        +trueChain.toString)
      println("confirmed chain hash: \n"+bytes2hex(FastCryptographicHash(serialize(localChain.drop(confirmationDepth)))))
      sender() ! "done"
    }

    /**sends coordinator keys */
    case GetGenKeys => {sender() ! diffuse(holderData,holderId,sk_sig)}

    case value:WriteFile => {
      value.fw match {
        case fileWriter: BufferedWriter => {
          val fileString = (
            holderIndex.toString+" "
              +t.toString+" "
              +alpha_Ep.toString+" "
              +blocksForged.toString+" "
              +localChain.length.toString+" "
              +bytes2hex(FastCryptographicHash(serialize(localChain.drop(confirmationDepth))))
            +"\n"
            )
          fileWriter.write(fileString)
        }
        case _ => println("error: data file writer not initialized")
      }
      sender() ! "done"
    }

    case _ => {println("received unknown message");sender() ! "error"}
  }

  /**Determines eligibility for a stakeholder to be a slot leader */
  def slotLeader: Boolean = {
    val slot = t
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta_Ep++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    compare(y,Tr_Ep)
  }

  /**Calculates a block */
  def forgeBlock: Block = {
    val blockTx:Tx = signTx(forgeBytes,serialize(holderId),sk_sig,pk_sig)
    val slot:Slot = t
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta_Ep++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta_Ep++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = FastCryptographicHash(serialize(localChain.head))
    val state:State = Map(blockTx->forgerReward)
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,stakingParty,Tr_Ep)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi)
    (hash,state,slot,cert,rho,pi,sig,pk_kes)
  }

}
