package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props}
import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.MalkinSignature
import util.control.Breaks._
import scala.util.Random
import java.io.BufferedWriter

/**
  * Stakeholder actor that executes the staking protocol and communicates with other stakeholders,
  * sends the coordinator the public key upon instantiation and gets the genesis block from coordinator
  */

class Stakeholder extends Actor
  with obMethods
  with stakeHolderVars {

  val holderId = s"${self.path}"

  /**Determines eligibility for a stakeholder to be a slot leader */
  def slotLeader: Boolean = {
    val slot = t
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta_Ep++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    compare(y,Tr_Ep)
  }

  /**Calculates a block with epoch variables*/
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
    },holderIndex,timingFlag)

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
    },holderIndex,timingFlag)

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
    },holderIndex,timingFlag)
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
    },holderIndex,timingFlag)

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
}

object Stakeholder {
  def props: Props = Props(new Stakeholder)
}

