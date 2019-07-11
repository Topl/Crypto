package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash

import util.control.Breaks._
import java.io.BufferedWriter

import io.iohk.iodb.ByteArrayWrapper

/**
  * Stakeholder actor that executes the staking protocol and communicates with other stakeholders,
  * sends the coordinator the public key upon instantiation and gets the genesis block from coordinator
  */

class Stakeholder extends Actor
  with Timers
  with obMethods
  with stakeHolderVars {

  val holderId = s"${self.path}"

  /** Determines eligibility for a stakeholder to be a slot leader */
  def slotLeader: Boolean = {
    val slot = currentSlot
    val pi_y: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"))
    val y: Rho = vrf.vrfProofToHash(pi_y)
    compare(y, Tr_Ep)
  }

  /** Calculates a block with epoch variables */
  def forgeBlock: Block = {
    val pb:Block = getBlock(localChain(lastActiveSlot(localChain,currentSlot-1)))
    val bn:Int = pb._9 + 1
    val ps:Slot = pb._3
    val blockTx: Tx = signTx(forgeBytes, serialize(holderId), sk_sig, pk_sig)
    val slot: Slot = currentSlot
    val pi: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"))
    val rho: Rho = vrf.vrfProofToHash(pi)
    val pi_y: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"))
    val y: Rho = vrf.vrfProofToHash(pi_y)
    val h: Hash = hash(pb)
    val state: State = Map(blockTx -> forgerReward)
    val cert: Cert = (pk_vrf, y, pi_y, pk_sig, Tr_Ep)
    val sig: MalkinSignature = kes.sign(malkinKey,h.data++serialize(state)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps))
    (h, state, slot, cert, rho, pi, sig, pk_kes,bn,ps)
  }
  
  def updateChain = {
    val ci = foreignChains.last
    var bool = true
    var tine:Chain = ci
    breakable{
      while(bool) {
        getParentId(tine.head) match {
          case pb:BlockId => {
            tine = Array(pb) ++ tine
          }
          case _ => bool = false
        }
        if (tine.head._2 == localChain(tine.head._1)._2 && tine.head._1 == localChain(tine.head._1)._1) { break }
      }
    }
    if (bool) {
      var trueChain = false
      if(tine.last._1 - tine.head._1 < confirmationDepth) {
        val prefixEp = tine.head._1/epochLength
        val eta_Ep_tmp:Eta = history(prefixEp)._1
        val stakingState_tmp:LocalState = history(prefixEp)._2
        if (prefixEp == currentEpoch) {
          trueChain = verifyChain(tine, stakingState_tmp, eta_Ep_tmp,prefixEp,stakingState,eta_Ep)
        } else {
          trueChain = verifyChain(tine, stakingState_tmp, eta_Ep_tmp,prefixEp,history(prefixEp+1)._2,history(prefixEp+1)._1)
        }
      } else {

      }
    } else {
      send(holderId, holders, RequestBlock(tine.head._2,tine.head._1,diffuse(holderData, holderId, sk_sig)))
    }
  }

  def updateSlot = {
    currentSlot = time
    if (holderIndex == 0) println("Slot = " + currentSlot.toString)
    time({
      updateEpoch
    }, holderIndex, timingFlag)
    if (holderIndex == 0 && printFlag) {
      println("Holder " + holderIndex.toString + " Update KES")
    }
    time({
      malkinKey = kes.updateKey(malkinKey, currentSlot)
    }, holderIndex, timingFlag)

    if (holderIndex == 0 && printFlag) {
      println("Holder " + holderIndex.toString + " ForgeBlocks")
    }
    time({
      if (diffuseSent) {
        if (slotLeader) {
          roundBlock = forgeBlock
          if (holderIndex == 0 && printFlag) {
            println("Holder " + holderIndex.toString + " is slot a leader")
          }
        }
        roundBlock match {
          case b: Block => {
            val hb = hash(b)
            blocks.update(currentSlot,blocks(currentSlot)+(hb->b))
            localChain.update(currentSlot,(currentSlot,hb))
            send(holderId, holders, SendBlock(b, diffuse(holderData, holderId, sk_sig)))
            blocksForged += 1
          }
          case _ =>
        }
      }
    }, holderIndex, timingFlag)
    roundBlock = 0
    if (dataOutFlag && currentSlot % dataOutInterval == 0) {
      coordinatorRef ! WriteFile
    }
  }

  def updateEpoch = {
    if (currentSlot / epochLength > currentEpoch) {
      currentEpoch = currentSlot / epochLength
      if (holderIndex == 0 && printFlag) println("Current Epoch = " + currentEpoch.toString)
      stakingState = updateLocalState(stakingState, subChain(localChain, (currentSlot / epochLength) * epochLength - 2 * epochLength + 1, (currentSlot / epochLength) * epochLength - epochLength))
      stakingState = activeStake(stakingState, subChain(localChain, (currentSlot / epochLength) * epochLength - 10 * epochLength + 1, (currentSlot / epochLength) * epochLength - epochLength))
      alpha_Ep = relativeStake((pk_sig, pk_vrf, pk_kes), stakingState)
      Tr_Ep = phi(alpha_Ep, f_s)
      eta_Ep = eta(localChain, currentEpoch, eta_Ep)
      history = history ++ List((eta_Ep, stakingState))
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " alpha = " + alpha_Ep.toString)
      }
    }
  }

  private case object timerKey

  def receive: Receive = {

    case value: CoordRef => {
      value.ref match {
        case r: ActorRef => coordinatorRef = r
        case _ =>
      }
      sender() ! "done"
    }

    case value: StartTime => {
      t0 = value.t0
      sender() ! "done"
    }

    case value: Run => {
      println("Holder "+holderIndex.toString+" starting...")
      tMax = value.max
      blocks = blocks++Array.fill(tMax){Map[ByteArrayWrapper,Block]()}
      localChain = Array((0,genBlockHash))++Array.fill(tMax){(-1,ByteArrayWrapper(Array()))}
      assert(genBlockHash == hash(blocks(0)(genBlockHash)))
      timers.startPeriodicTimer(timerKey, Update, updateTime)
      sender() ! "done"
    }

    case value: GetTime => {
      time = ((value.t1 - t0) / slotT).toInt
    }

    /** updates time, the kes key, and resets variables */
    case Update => {

      if (!updating) {
        updating = true
        if (time > tMax) {
          timers.cancelAll
        } else {
          if (!diffuseSent) {
            send(holderId, holders, diffuse(holderData, holderId, sk_sig))
            diffuseSent = true
          }
          coordinatorRef ! GetTime
          if (time > currentSlot) {
            updateSlot
          } else if (foreignChains.nonEmpty) {
            if (holderIndex == 0 && printFlag) {
              println("Holder " + holderIndex.toString + " Update Chain")
            }
            time({
              updateChain
            }, holderIndex, timingFlag)
          }
        }
        updating = false
      }
    }

    /** receives chains from other holders and stores them */
    case value: SendChain => {
      if (verifyTxStamp(value.s) && inbox.contains(idInfo(value.s))) {
        if (holderIndex == 0 && printFlag) {
          println("Holder " + holderIndex.toString + " Received Chain")
        }
        if (updating) println("ERROR: received chain executing while updating")
        value.c match {
          case c: Chain => {
            foreignChains = foreignChains ++ List(c)
          }
          case _ => println("error")
        }
      }
    }

    case value: SendBlock => if (verifyTxStamp(value.s) && inbox.contains(idInfo(value.s))) {
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " Received Block")
      }
      if (updating) println("ERROR: executing while updating")
      value.b match {
        case b: Block => {
          if (verifyBlock(b)) {
            val bHash = hash(b)
            val bSlot = b._3
            val pSlot = b._10
            val pHash = b._1
            val foundBlock = blocks(bSlot).contains(bHash)
            if (!foundBlock && bSlot <= currentSlot) blocks.update(bSlot, blocks(bSlot) + (bHash->b))
            if (bSlot <= currentSlot && bSlot > lastActiveSlot(localChain,currentSlot)) foreignChains ::= (bSlot,bHash)
            val foundParent = blocks(pSlot).contains(pHash)
            if (!foundParent) sender() ! RequestBlock(pHash,pSlot,diffuse(holderData, holderId, sk_sig))
          }
        }
        case _ => println("error")
      }
    }

    case value: RequestBlock =>  if (verifyTxStamp(value.s) && inbox.contains(idInfo(value.s))) {
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " Requested Block")
      }
      if (updating) println("ERROR: executing while updating")
      if (blocks(value.slot).contains(value.h)) {
        sender() ! SendBlock(blocks(value.slot)(value.h),diffuse(holderData, holderId, sk_sig))
      }
    }

    /** validates diffused string from other holders and stores in inbox */
    case value: String => {
      if (verifyTxStamp(value)) inbox = inbox + value + "\n"
    }

    /** accepts list of other holders from coordinator */
    case list: List[ActorRef] => {
      holders = list
      var i = 0
      for (holder <- holders) {
        if (holderId == s"${holder.path}") holderIndex = i
        i += 1
      }
      sender() ! "done"
    }

    /** accepts genesis block from coordinator */
    case gb: GenBlock => {
      genBlock = gb.b
      genBlock match {
        case b: Block => {
          genBlockHash = hash(b)
          blocks = Array(Map(genBlockHash->b))
        }
        case _ => println("error")
      }
      sender() ! "done"
    }

    /** prints inbox */
    case Inbox => {
      println(inbox); sender() ! "done"
    }

    /** prints stats */
    case Status => {
      val trueChain = verifyChain(localChain, genBlockHash)
      println(holderId + "\nt = " + currentSlot.toString + " alpha = " + alpha_Ep.toString + " blocks forged = "
        + blocksForged.toString + "\n chain length = " + localChain.length.toString + " valid chain = "
        + trueChain.toString)
      var chainBytes:Array[Byte] = Array()
      for (sh <- subChain(localChain,0,currentSlot-confirmationDepth)) {
        getBlock(sh) match {
          case b:Block => chainBytes ++= serialize(b)
          case _ =>
        }
      }
      println("confirmed chain hash: \n" + bytes2hex(FastCryptographicHash(chainBytes)))
      sender() ! "done"
    }

    /** sends coordinator keys */
    case GetGenKeys => {
      sender() ! diffuse(holderData, holderId, sk_sig)
    }

    case value: WriteFile => {
      value.fw match {
        case fileWriter: BufferedWriter => {
          val fileString = (
            holderIndex.toString + " "
              + currentSlot.toString + " "
              + alpha_Ep.toString + " "
              + blocksForged.toString + " "
              + localChain.length.toString + " "
              + bytes2hex(FastCryptographicHash(serialize(localChain.drop(confirmationDepth))))
              + "\n"
            )
          fileWriter.write(fileString)
        }
        case _ => println("error: data file writer not initialized")
      }
    }

    case _ => {
      println("received unknown message"); sender() ! "error"
    }
  }
}

object Stakeholder {
  def props: Props = Props(new Stakeholder)
}

