package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash
import util.control.Breaks._
import java.io.BufferedWriter

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
    val blockTx: Tx = signTx(forgeBytes, serialize(holderId), sk_sig, pk_sig)
    val slot: Slot = currentSlot
    val pi: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"))
    val rho: Rho = vrf.vrfProofToHash(pi)
    val pi_y: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"))
    val y: Rho = vrf.vrfProofToHash(pi_y)
    val hash: Hash = FastCryptographicHash(serialize(localChain.head))
    val state: State = Map(blockTx -> forgerReward)
    val cert: Cert = (pk_vrf, y, pi_y, pk_sig, Tr_Ep)
    val sig: MalkinSignature = kes.sign(malkinKey, hash ++ serialize(state) ++ serialize(slot) ++ serialize(cert) ++ rho ++ pi)
    (hash, state, slot, cert, rho, pi, sig, pk_kes)
  }

  def updateChain = {
    time({
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " Update Chain")
      }
      for (chain <- foreignChains) {
        if (chain.length > localChain.length) {
          var trueChain = false
          if (localChain.length == 1) {
            if (holderIndex == 0 && printFlag) {
              println("Inheriting chain")
            }
            trueChain = verifyChain(chain, genBlockHash)
          } else {
            var prefixIndex = 0
            var foundCommonPrefix = false
            breakable {
              for (block <- chain.drop(chain.length - localChain.length)) {
                if (block._1.deep == localChain(prefixIndex)._1.deep) {
                  if (holderIndex == 0 && printFlag) {
                    println("Found ancestor at i = " + prefixIndex.toString)
                  }
                  foundCommonPrefix = true
                  val eta_Ep_tmp = history(block._3/epochLength)._1
                  val stakingState_tmp = history(block._3/epochLength)._2
                  trueChain = verifyChain(chain.take(prefixIndex+chain.length - localChain.length), stakingState_tmp, eta_Ep_tmp,block._3/epochLength,stakingState,eta_Ep)
                  break
                }
                prefixIndex += 1
              }
            }
            if (!foundCommonPrefix) {
              if (holderIndex == 0 && printFlag) {
                println("No prefix found, checking entire chain")
              }
              trueChain = verifyChain(chain, genBlockHash)
            }
          }
          if (!trueChain) println("ERROR: invalid chain")
          assert(trueChain)
          if (trueChain) localChain = chain
        }
      }
      foreignChains = List()
    }, holderIndex, timingFlag)
  }

  def updateSlot = {
    time({
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " Update Slot")
      }
      currentSlot = time
      if (holderIndex == 0) println("Slot = " + currentSlot.toString)
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " Update")
      }

      /** checks eligibility to forge blocks and sends chain to other holders if a new block is forged */
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " ForgeBlocks")
      }

      if (currentSlot/epochLength > currentEpoch) {
        currentEpoch = currentSlot / epochLength
        if (holderIndex == 0 && printFlag) println("Current Epoch = " + currentEpoch.toString)
        val txString = diffuse(holderData, holderId, sk_sig)

        stakingState = updateLocalState(stakingState, subChain(localChain, (currentSlot / epochLength) * epochLength - 2 * epochLength + 1, (currentSlot / epochLength) * epochLength - epochLength))
        alpha_Ep = relativeStake((pk_sig,pk_vrf,pk_kes),stakingState)
        Tr_Ep = phi(alpha_Ep, f_s)
        eta_Ep = eta(localChain,currentEpoch,eta_Ep)
        history = history++List((eta_Ep,stakingState))

        if (holderIndex == 0 && printFlag) {
          println("holder " + holderIndex.toString + " alpha = " + alpha_Ep.toString)
          //val (stakingState0,memPool0) = revertLocalState(stakingState, subChain(localChain, (currentSlot / epochLength) * epochLength - 2 * epochLength + 1, (currentSlot / epochLength) * epochLength - epochLength),memPool)
          //stakingState = stakingState0
          //stakingState = updateLocalState(stakingState, subChain(localChain, (currentSlot / epochLength) * epochLength - 2 * epochLength + 1, (currentSlot / epochLength) * epochLength - epochLength))
          //assert(alpha_Ep == relativeStake(stakingParty,(pk_sig,pk_vrf,pk_kes),stakingState))
        }
      }
      malkinKey = kes.updateKey(malkinKey, currentSlot)
      if (diffuseSent) {
        if (slotLeader) {
          roundBlock = forgeBlock
          if (holderIndex == 0 && printFlag) {
            println("Holder " + holderIndex.toString + " is slot a leader")
          }
        }
        roundBlock match {
          case b: Block => {
            localChain = List(b) ++ localChain
            send(holderId, holders, SendChain(localChain, diffuse(holderData, holderId, sk_sig)))
            blocksForged += 1
          }
          case _ =>
        }
      }
      roundBlock = 0
      if (dataOutFlag && currentSlot % dataOutInterval == 0) {
        coordinatorRef ! WriteFile
      }
    }, holderIndex, timingFlag)
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
      tMax = value.max
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
            updateChain
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
          localChain = List(b) ++ localChain
          genBlockHash = FastCryptographicHash(serialize(genBlock))
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
      println("confirmed chain hash: \n" + bytes2hex(FastCryptographicHash(serialize(localChain.drop(confirmationDepth)))))
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

