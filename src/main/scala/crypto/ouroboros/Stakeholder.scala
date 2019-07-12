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
    val pb:Block = getBlock(localChain(lastActiveSlot(localChain,currentSlot-1))) match {case b:Block => b}
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
    var tine:Chain = Array(ci)
    var prefix:Slot = 0
    breakable{
      while(bool) {
        getParentId(tine.head) match {
          case pb:BlockId => {
            tine = Array(pb) ++ tine
            if (tine.head == localChain(tine.head._1)) {
              prefix = tine.head._1
              tine = tine.tail
              break
            }
            if (tine.head._1 == 0) {
              prefix = 0
              tine = tine.tail
              break
            }
          }
          case _ => bool = false
        }
      }
    }
    if (bool) {
      var trueChain = false
      val s0 = tine.head._1
      val s1 = tine.last._1
      val bnt = {getBlock(tine.last) match {case b:Block => b._9}}
      val bnl = {getBlock(localChain(lastActiveSlot(localChain,currentSlot))) match {case b:Block => b._9}}
      if(s1 - prefix < confirmationDepth && bnl < bnt) {
        trueChain = true
      } else if (getActiveSlots(tine) > getActiveSlots(subChain(localChain,prefix,currentSlot))) {
        trueChain = true
      }
      if (trueChain) {
        val ep0 = s0 / epochLength
        val eta0: Eta = history(ep0)._1
        val stakingState_tmp: LocalState = history(ep0)._2
        if (ep0 == currentEpoch) {
          trueChain &&= verifyChain(tine, stakingState_tmp, eta0, ep0, stakingState, eta_Ep)
        } else {
          trueChain &&= verifyChain(tine, stakingState_tmp, eta0, ep0, history(ep0 + 1)._2, history(ep0 + 1)._1)
        }
      }
      if(trueChain) {
        for (i <- prefix+1 to currentSlot) {
          localChain.update(i,(-1,ByteArrayWrapper(Array())))
        }
        for (id <- tine) {
          localChain.update(id._1,id)
        }
      }
      foreignChains = foreignChains.dropRight(1)
    } else {
      send(holderId, holders, RequestBlock(tine.head._2,tine.head._1,diffuse(holderData, holderId, sk_sig)))
    }
  }

  def updateSlot = {
    currentSlot = time
    if (holderIndex == 0) println("Slot = " + currentSlot.toString)
    time(
      updateEpoch
    )
    if (holderIndex == 0 && printFlag) {
      println("Holder " + holderIndex.toString + " Update KES")
    }
    time(
      malkinKey = kes.updateKey(malkinKey, currentSlot)
    )

    if (holderIndex == 0 && printFlag) {
      println("Holder " + holderIndex.toString + " ForgeBlocks")
    }
    time(
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
    )
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
      //println("Holder "+holderIndex.toString+" eta A: "+bytes2hex(eta_Ep))
      //println("Holder "+holderIndex.toString+" eta B: "+bytes2hex(eta(localChain,currentEpoch)))
//      var chainBytes:Array[Byte] = Array()
//      for (id <- subChain(localChain,0,currentSlot-confirmationDepth)) {
//        getBlock(id) match {
//          case b:Block => chainBytes ++= serialize(b)
//          case _ =>
//        }
//      }
//      println("Holder "+holderIndex.toString+" confirmed chain hash: " + bytes2hex(FastCryptographicHash(chainBytes)))
//      println("Holder "+holderIndex.toString+" verify chain: "+verifyChain(localChain,genBlockHash))
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
            time(
              updateChain
            )
          }
        }
        updating = false
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
            if (!foundBlock) blocks.update(bSlot, blocks(bSlot) + (bHash->b))
            if (!foundBlock && bSlot <= currentSlot) {
              val newId = (bSlot,bHash)
              foreignChains ::= newId
            }
            val foundParent = blocks(pSlot).contains(pHash)
            if (!foundBlock && !foundParent) {
              val requesterId = idPath(value.s)
              var requesterRef:Any = 0
              for (holder <- holders) {
                if (requesterId == s"${holder.path}") requesterRef = holder
              }
              requesterRef match {
                case ref:ActorRef => {
                  ref ! RequestBlock(pHash,pSlot,diffuse(holderData, holderId, sk_sig))
                }
                case _ =>
              }
            }
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
      val requesterId = idPath(value.s)
      var requesterRef:Any = 0
      for (holder <- holders) {
        if (requesterId == s"${holder.path}") requesterRef = holder
      }
      requesterRef match {
        case ref:ActorRef => {
          if (blocks(value.slot).contains(value.h)) {
            ref ! SendBlock(blocks(value.slot)(value.h),diffuse(holderData, holderId, sk_sig))
          }
        }
        case _ =>
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
      println("Holder "+holderIndex.toString + ": t = " + currentSlot.toString + ", alpha = " + alpha_Ep.toString + ", blocks forged = "
        + blocksForged.toString + "\nChain length = " + getActiveSlots(localChain).toString + ", Valid chain = "
        + trueChain.toString)
      var chainBytes:Array[Byte] = Array()
      for (id <- subChain(localChain,0,currentSlot-confirmationDepth)) {
        getBlock(id) match {
          case b:Block => chainBytes ++= FastCryptographicHash(serialize(b))
          case _ =>
        }
      }
      println("Chain hash: " + bytes2hex(FastCryptographicHash(chainBytes))+"\n")
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
              + getActiveSlots(localChain).toString + " "
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

