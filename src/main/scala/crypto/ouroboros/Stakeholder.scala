package crypto.ouroboros

import akka.actor.{Actor, ActorPath, ActorRef, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash

import util.control.Breaks._
import java.io.BufferedWriter

import scala.util.Random
import scala.collection.immutable.ListMap
import io.iohk.iodb.ByteArrayWrapper

import scala.math.BigInt

/**
  * Stakeholder actor that executes the staking protocol and communicates with other stakeholders,
  * sends the coordinator the public key upon instantiation and gets the genesis block from coordinator
  */

class Stakeholder(seed:Array[Byte]) extends Actor
  with Timers
  with obMethods
  with stakeHolderVars {
  val (sk_vrf,pk_vrf) = vrf.vrfKeypair(seed)
  var malkinKey:MalkinKey = kes.generateKey(seed)
  val (sk_sig,pk_sig) = sig.createKeyPair(seed)
  val pk_kes:PublicKey = kes.publicKey(malkinKey)
  val holderId:ActorPath = self.path
  val sessionId:Sid = ByteArrayWrapper(FastCryptographicHash(holderId.toString))
  val publicKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  val pkw:PublicKeyW = ByteArrayWrapper(pk_sig++pk_vrf++pk_kes)

  /** Determines eligibility for a stakeholder to be a slot leader */
  /** Calculates a block with epoch variables */
  def forgeBlock = {
    val slot = currentSlot
    val pi_y: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"))
    val y: Rho = vrf.vrfProofToHash(pi_y)
    if (compare(y, Tr_Ep)) {
      roundBlock = {
        val pb:Block = getBlock(localChain(lastActiveSlot(localChain,currentSlot-1))) match {case b:Block => b}
        val bn:Int = pb._9 + 1
        val ps:Slot = pb._3
        val blockTx: Tx = signTx((forgeBytes,BigDecimal(forgerReward).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt), sessionId, sk_sig, pk_sig)
        val pi: Pi = vrf.vrfProof(sk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"))
        val rho: Rho = vrf.vrfProofToHash(pi)
        val h: Hash = hash(pb)
        var ledger: Ledger = List()
        var ls: LocalState = localState
        for (entry<-ListMap(memPool.toSeq.sortWith(_._2._5 < _._2._5):_*)) {
          if (entry._2._5 == ls(entry._2._1)._3) {
            ls = applyTransfer(ls,entry._2,pkw)
          }
          ledger ::= entry._2
          memPool -= entry._1
        }
        ledger = ledger.reverse
        ledger ::= blockTx
        val cert: Cert = (pk_vrf, y, pi_y, pk_sig, Tr_Ep)
        val sig: MalkinSignature = kes.sign(malkinKey,h.data++serialize(ledger)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps))
        (h, ledger, slot, cert, rho, pi, sig, pk_kes,bn,ps)
      }
      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " is slot a leader")
      }
    }
    roundBlock match {
      case b: Block => {
        val hb = hash(b)
        blocks.update(currentSlot, blocks(currentSlot) + (hb -> b))
        localChain.update(currentSlot, (currentSlot, hb))
        send(holderId, gossipers, SendBlock(signTx((b,(currentSlot, hb)), sessionId, sk_sig, pk_sig)))
        blocksForged += 1
      }
      case _ =>
    }
    roundBlock = 0
  }

  def updateChain = {
    var bool = true
    var tine:Chain = foreignChains.last._1
    var counter:Int = foreignChains.last._2
    val previousLen:Int = foreignChains.last._3
    val totalTries:Int = foreignChains.last._4
    val ref:ActorRef = foreignChains.last._5
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
          case _ => {
            if (tine.length == previousLen) {counter+=1} else {counter=0}
            bool = false
          }
        }
      }
    }
    if (bool) {
      tine = expand(tine,prefix)
      var trueChain = false
      val s1 = tine.last._1
      val bnt = {getBlock(tine.last) match {case b:Block => b._9}}
      val bnl = {getBlock(localChain(lastActiveSlot(localChain,currentSlot))) match {case b:Block => b._9}}
      if(s1 - prefix < k_s && bnl < bnt) {
        trueChain = true
      } else {
        val slotsTine = getActiveSlots(subChain(tine,0,slotWindow))
        val slotsLocal = getActiveSlots(subChain(localChain,prefix+1,prefix+1+slotWindow))
        if (slotsLocal < slotsTine) {
          trueChain = true
        }
      }
      if (trueChain) {
        trueChain &&= verifySubChain(tine,prefix)
      }
      if (trueChain) {
        if (holderIndex == 0 && printFlag) println("Holder " + holderIndex.toString + " Adopting Tine")
        collectState(subChain(localChain,prefix+1,currentSlot))
        collectState(tine)

        for (i <- prefix+1 to currentSlot) {
          localChain.update(i,(-1,ByteArrayWrapper(Array())))
        }
        for (id <- tine) {
          if (id._1 > -1) {
            localChain.update(id._1,id)
            getBlock(id) match {
              case b:Block => {
                val blockState = b._2
                for (entry<-blockState.tail) {
                  entry match {
                    case trans:Transfer => {
                      if (memPool.keySet.contains(trans._4)) {
                        memPool -= trans._4
                      }
                    }
                    case _ =>
                  }
                }
              }
              case _ =>
            }
          }
        }
        localState = history_state(prefix)
        eta_Ep = history_eta(prefix/epochLength)
        currentSlot = prefix
        currentEpoch = currentSlot/epochLength
      } else {
        collectState(tine)
        for (id <- subChain(localChain,prefix+1,currentSlot)) {
          if (id._1 > -1) {
            getBlock(id) match {
              case b: Block => {
                val blockState = b._2
                for (entry <- blockState.tail) {
                  entry match {
                    case trans: Transfer =>  {
                      if (memPool.keySet.contains(trans._4)){
                        memPool -= trans._4
                      }
                    }
                    case _ =>
                  }
                }
              }
              case _ =>
            }
          }
        }
      }
      foreignChains = foreignChains.dropRight(1)
    } else {
      if (counter>tineMaxTries) {
        if (holderIndex == 0 && printFlag) println("Holder " + holderIndex.toString + " Dropping Tine")
        foreignChains = foreignChains.dropRight(1)
      } else {
        foreignChains.update(foreignChains.length-1,(tine,counter,tine.length,totalTries+1,ref))
        if (totalTries > k_s/5) {
          if (holderIndex == 0 && printFlag) println(
            "Holder " + holderIndex.toString + " Looking for Parent Chain C:"+counter.toString+"L:"+tine.length
          )
          val depth:Int = if (totalTries - k_s/5 < tineMaxDepth) {
            totalTries - k_s/5
          } else {
            tineMaxDepth
          }
          val request:ChainRequest = (tine.head._1-1,depth)
          send(holderId, List(ref), RequestChain(signTx(request,sessionId,sk_sig,pk_sig)))
        } else {
          if (holderIndex == 0 && printFlag) println("Holder " + holderIndex.toString + " Looking for Parent Block C:"+counter.toString+"L:"+tine.length)
          send(holderId,List(ref), RequestBlock(signTx(tine.head,sessionId,sk_sig,pk_sig)))
        }
      }
    }
  }

  def updateSlot = {
    if (holderIndex == 0 && currentSlot == time) println("Slot = " + currentSlot.toString)
    time(
      updateEpoch
    )
    if (currentSlot == time) {
      time(if (kes.getKeyTimeStep(malkinKey) < currentSlot) {
        if (holderIndex == 0 && printFlag) {
          println("Holder " + holderIndex.toString + " Update KES")
        }
        malkinKey = kes.updateKey(malkinKey, currentSlot)
      })

      time(if (foreignChains.isEmpty) {
        if (holderIndex == 0 && printFlag) {println("Holder " + holderIndex.toString + " ForgeBlocks")}
        forgeBlock
      })
    }
    localState = updateLocalState(localState, Array(localChain(currentSlot)))
    issueState = localState
    if (dataOutFlag && time % dataOutInterval == 0) {
      coordinatorRef ! WriteFile
    }
  }

  def updateEpoch = {
    if (currentSlot / epochLength > currentEpoch) {
      currentEpoch = currentSlot / epochLength
      if (holderIndex == 0 && printFlag) println("Current Epoch = " + currentEpoch.toString)
      stakingState = {
        if (currentEpoch > 1) {history_state((currentEpoch-1)*epochLength)} else {history_state(0)}
      }
      alpha_Ep = relativeStake((pk_sig, pk_vrf, pk_kes), stakingState)
      Tr_Ep = phi(alpha_Ep, f_s)
      if (currentEpoch > 0) {
        eta_Ep = eta(localChain, currentEpoch, history_eta(currentEpoch-1))
        history_eta.update(currentEpoch,eta_Ep)
      }

      if (holderIndex == 0 && printFlag) {
        println("Holder " + holderIndex.toString + " alpha = " + alpha_Ep.toString+"\nEta:"+bytes2hex(eta_Ep))
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
      history_eta = Array.fill(tMax/epochLength+1){Array()}
      history_state = Array.fill(tMax+1){Map()}
      assert(genBlockHash == hash(blocks(0)(genBlockHash)))
      localState = updateLocalState(localState, Array(localChain(0)))
      eta_Ep = eta(localChain, 0, Array())
      history_state.update(0,localState)
      history_eta.update(0,eta_Ep)
      timers.startPeriodicTimer(timerKey, Update, updateTime)
      sender() ! "done"
    }

    case value: GetTime => if (!actorStalled) {
      time = ((value.t1 - t0) / slotT).toInt
    }

    /** updates time, the kes key, and resets variables */
    case Update => { if (sharedData.error) {actorStalled = true}
      if (!actorStalled) {
        if (!updating) {
          updating = true
          if (time > tMax) {
            timers.cancelAll
          } else if (diffuseSent) {
            coordinatorRef ! GetTime
            if (time > currentSlot) {
              while (time > currentSlot) {
                history_state.update(currentSlot,localState)
                currentSlot += 1
                updateSlot
              }
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
    }

    case value: SendBlock => if (!actorStalled) {
      value.s match {
        case s:Tx => if (inbox.keySet.contains(s._2)) {
          s._1 match {
            case bInfo: (Block,BlockId) => {
              val bid:BlockId = bInfo._2
              val foundBlock = blocks(bid._1).contains(bid._2)
              if (!foundBlock) {
                val b:Block = bInfo._1
                val bHash = hash(b)
                val bSlot = b._3
                if (verifyTx(s) && verifyBlock(b) && bHash == bid._2 && bSlot == bid._1) {
                  if (!foundBlock) blocks.update(bSlot, blocks(bSlot) + (bHash -> b))
                  if (!foundBlock && bSlot <= time) {
                    if (holderIndex == 0 && printFlag) {
                      println("Holder " + holderIndex.toString + " Received Block")
                    }
                    val newId = (bSlot, bHash)
                    send(holderId, gossipers, SendBlock(signTx((b,newId), sessionId, sk_sig, pk_sig)))
                    foreignChains = Array((Array(newId),0,0,0,inbox(s._2)._1))++foreignChains
                  }
                }
              }
            }
            case _ =>
          }
        }
        case _ =>
      }
    }

    case value: ReturnBlock => if (!actorStalled) {
      value.s match {
        case s:Tx => if (inbox.keySet.contains(s._2)) {
          s._1 match {
            case bInfo: (Block,BlockId) => {
              val bid:BlockId = bInfo._2
              val foundBlock = blocks(bid._1).contains(bid._2)
              if (!foundBlock) {
                val b:Block = bInfo._1
                val bHash = hash(b)
                val bSlot = b._3
                if (verifyTx(s) && verifyBlock(b) && bHash == bid._2 && bSlot == bid._1) {
                  if (!foundBlock) {
                    blocks.update(bSlot, blocks(bSlot) + (bHash -> b))
                    if (holderIndex == 0 && printFlag) {
                      println("Holder " + holderIndex.toString + " Got Block Back")
                    }
                  }
                }
              }
            }
            case bList: List[(Block,BlockId)] => {
              if (holderIndex == 0 && printFlag) {
                println("Holder " + holderIndex.toString + " Got Blocks Back")
              }
              for (bInfo <- bList) {
                val bid:BlockId = bInfo._2
                val foundBlock = blocks(bid._1).contains(bid._2)
                if (!foundBlock) {
                  val b:Block = bInfo._1
                  val bHash = hash(b)
                  val bSlot = b._3
                  if (verifyTx(s) && verifyBlock(b) && bHash == bid._2 && bSlot == bid._1) {
                    if (!foundBlock) {
                      blocks.update(bSlot, blocks(bSlot) + (bHash -> b))
                    }
                  }
                }
              }
            }
            case _ =>
          }
        }
        case _ =>
      }
    }

    case value: RequestBlock => if (!actorStalled) {
      value.s match {
        case s:Tx => {
          if (inbox.keySet.contains(s._2)) {
            if (holderIndex == 0 && printFlag) {
              println("Holder " + holderIndex.toString + " Was Requested Block")
            }
            val ref = inbox(s._2)._1
            s._1 match {
              case id:BlockId => {
                if (blocks(id._1).contains(id._2)) {
                  if (verifyTx(s)) {
                    val returnedBlock = blocks(id._1)(id._2)
                    ref ! ReturnBlock(signTx((returnedBlock,id),sessionId,sk_sig,pk_sig))
                    if (holderIndex == 0 && printFlag) {
                      println("Holder " + holderIndex.toString + " Returned Block")
                    }
                  }
                }
              }
              case _ =>
            }
          }
        }
        case _ =>
      }
    }

    case value: RequestChain => if (!actorStalled) {
      value.s match {
        case s:Tx => {
          if (inbox.keySet.contains(s._2)) {
            if (holderIndex == 0 && printFlag) {
              println("Holder " + holderIndex.toString + " Was Requested Blocks")
            }
            val ref = inbox(s._2)._1
            s._1 match {
              case entry:ChainRequest => {
                val depth:Int = entry._2
                val slot:Slot = entry._1
                if (depth <= tineMaxDepth) {
                  if (verifyTx(s)) {
                    var returnedBlockList:List[(Block,BlockId)] = List()
                    for (bid:BlockId<-subChain(localChain,slot-k_s*depth,slot)) {
                      if (bid._1 > -1) {
                        val block = getBlock(bid) match {case b:Block => b}
                        returnedBlockList ::= (block,bid)
                      }
                    }
                    ref ! ReturnBlock(signTx(returnedBlockList,sessionId,sk_sig,pk_sig))
                    if (holderIndex == 0 && printFlag) {
                      println("Holder " + holderIndex.toString + " Returned Blocks")
                    }
                  }
                }
              }
              case _ =>
            }
          }
        }
        case _ =>
      }
    }

    case value: IssueTx => if (!actorStalled) {
      value.s match {
        case data:(PublicKeyW,BigInt) => {
          val (pk_r,delta) = data
          val net = issueState(pkw)._1
          val txC = issueState(pkw)._3
          if (delta <= net) {
            if (holderIndex==0 && printFlag) {println(s"Holder $holderIndex Issued Transaction")}
            val trans:Transfer = signTransfer(sk_sig,pkw,pk_r,delta,txC)
            issueState = applyTransfer(issueState,trans,pk_r)
            txCounter += 1
            send(holderId, gossipers, SendTx(trans))
          }
        }
      }
    }

    case value: SendTx => if (!actorStalled) {
      value.s match {
        case trans:Transfer => {
          if (!memPool.keySet.contains(trans._4)) {
            val delta:BigInt = trans._3
            val pk_s:PublicKeyW = trans._1
            val net = localState(pk_s)._1
            if (delta<=net) {
              if (verifyTransfer(trans)) {
                memPool += (trans._4->trans)
                send(holderId, gossipers, SendTx(value.s))
              }
            }
          }
        }
        case _ =>
      }
    }

    /** validates diffused string from other holders and stores in inbox */
    case value: Tx => {
      if (verifyTx(value) && !inbox.keySet.contains(value._2)) {
        val sid = value._2
        value._1 match {
          case d:(ActorRef,PublicKeys) => inbox += (sid->d)
          case _ =>
        }
      }
      sender() ! "done"
    }

    /** accepts list of other holders from coordinator */
    case list: List[ActorRef] => {
      holders = list
      gossipers = gossipSet(holderId,holders)
      var i = 0
      for (holder <- holders) {
        if (self == holder) holderIndex = i
        i += 1
      }
      sender() ! "done"
    }

    case value:Party => {
      value.list match {
        case list: List[ActorRef] => {
          holders = list
          gossipers = gossipSet(holderId,holders)
          if (value.clear) inbox = Map()
          diffuseSent = false
        }
        case _ =>
      }
      sender() ! "done"
    }

    case Diffuse => {
      sendAndWait(holderId, holders, signTx((self,publicKeys), sessionId, sk_sig, pk_sig))
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
      var i = 0
      println("Holder "+holderIndex.toString+":"+bytes2hex(sessionId.data))
      for (entry <- inbox) {
        println(i.toString+" "+bytes2hex(entry._1.data))
        i+=1
      }
      println("")
      sender() ! "done"
    }

    /** prints stats */
    case Verify => {
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
      //println("Public Key: "+bytes2hex(pk_sig++pk_vrf++pk_kes))
      println("Chain hash: " + bytes2hex(FastCryptographicHash(chainBytes))+"\n")
      if (sharedData.error){
        for (id <- localChain) {
          if (id._1 > -1) println("H:" + holderIndex.toString + "S:" + id._1.toString + "ID:" + bytes2hex(id._2.data))
        }
        for (e <- history_eta) {
          if (!e.isEmpty) println("H:" + holderIndex.toString + "E:" + bytes2hex(e))
        }
        println("e:" + bytes2hex(eta(localChain, currentEpoch)) + "\n")
      }
      sender() ! "done"
    }

    /** prints stats */
    case Status => {
      println("Holder "+holderIndex.toString + ": t = " + currentSlot.toString + ", alpha = " + alpha_Ep.toString + ", blocks forged = "
        + blocksForged.toString + "\nChain length = " + getActiveSlots(localChain).toString+", MemPool Size = "+memPool.size)
      var chainBytes:Array[Byte] = Array()
      for (id <- subChain(localChain,0,currentSlot-confirmationDepth)) {
        getBlock(id) match {
          case b:Block => {
            chainBytes ++= FastCryptographicHash(serialize(b))
          }
          case _ =>
        }
      }
      sharedData.txCounter += txCounter
      var txCount = 0
      var allTx:List[Sid] = List()
      var duplicatesFound = false
      var allTxSlots:List[Slot] = List()
      for (id <- subChain(localChain,0,currentSlot)) {
        getBlock(id) match {
          case b:Block => {
            val state = b._2
            for (entry<-state) {
              entry match {
                case trans:Transfer => {
                  if (!allTx.contains(trans._4)) {
                    allTx ::= trans._4
                    allTxSlots ::= b._3
                    txCount+=1
                  } else {
                    duplicatesFound = true
                    //println("Dup found at "+b._3.toString)
                    val dupIndex = allTx.indexOf(trans._4)
                    //println("Matches entry at "+allTxSlots(dupIndex))
                  }
                }
                case _ =>
              }
            }
          }
          case _ =>
        }
      }
      println(s"Transactions on chain: $txCount, duplicates: $duplicatesFound")
      println("Chain hash: " + bytes2hex(FastCryptographicHash(chainBytes))+"\n")
      if (false){
        for (id <- localChain) {
          if (id._1 > -1) {
            println("S:" + id._1.toString)
            getBlock(id) match {
              case b:Block => {
                for (entry<-b._2) {
                  entry match {
                    case trans:Transfer => println(bytes2hex(trans._4.data)+":"+trans._3.toString)
                    case _ =>
                  }
                }
              }
              case _ => println("error")
            }
          }
        }
      }
      sender() ! "done"
    }

    /** sends coordinator keys */
    case GetGenKeys => {
      sender() ! diffuse(bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes), s"{$holderId}", sk_sig)
    }

    case value: WriteFile => if (!actorStalled) {
      value.fw match {
        case fileWriter: BufferedWriter => {
          val fileString = (
            holderIndex.toString + " "
              + time.toString + " "
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

    case StallActor => {
      if (!actorStalled) {actorStalled = true}
      else {actorStalled = false}
      sender() ! "done"
    }

    case _ => if (!actorStalled) {
      println("received unknown message"); sender() ! "error"
    }
  }
}

object Stakeholder {
  def props(seed:Array[Byte]): Props = Props(new Stakeholder(seed))
}

