package crypto.ouroboros

import akka.actor.{Actor, ActorPath, ActorRef, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash
import util.control.Breaks._
import java.io.BufferedWriter
import io.iohk.iodb.ByteArrayWrapper
import scala.math.BigInt
import scala.util.Random
import scorex.crypto.encode.Base58

/**
  * Stakeholder actor that executes the staking protocol and communicates with other stakeholders,
  * sends the coordinator the public key upon instantiation and gets the genesis block from coordinator
  */

class Stakeholder(seed:Array[Byte]) extends Actor
  with Timers
  with Methods
  with StakeholderVariables {
  val (sk_vrf,pk_vrf) = vrf.vrfKeypair(seed)
  var sk_kes:KesKey = kes.generateKey(seed)
  val (sk_sig,pk_sig) = sig.createKeyPair(seed)
  val pk_kes:PublicKey = kes.publicKey(sk_kes)
  val holderId:ActorPath = self.path
  val sessionId:Sid = ByteArrayWrapper(FastCryptographicHash(holderId.toString))
  val publicKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  val pkw:PublicKeyW = ByteArrayWrapper(pk_sig++pk_vrf++pk_kes)
  rng = new Random(BigInt(seed).toLong)
  val phase:Double = rng.nextDouble
  var chainUpdateLock = false

  private case object timerKey

  /**determines eligibility for a stakeholder to be a slot leader then calculates a block with epoch variables */
  def forgeBlock = {
    val slot = localSlot
    val pi_y: Pi = vrf.vrfProof(sk_vrf, eta ++ serialize(slot) ++ serialize("TEST"))
    val y: Rho = vrf.vrfProofToHash(pi_y)
    if (compare(y, threshold)) {
      roundBlock = {
        val blockInfo = "forger index: "+holderIndex.toString+" eta used: "+Base58.encode(eta)+" epoch forged: "+currentEpoch.toString
        val pb:Block = getBlock(localChain(lastActiveSlot(localChain,localSlot-1))) match {case b:Block => b}
        val bn:Int = pb._9 + 1
        val ps:Slot = pb._3
        val blockBox: Box = signBox((forgeBytes,BigDecimal(forgerReward).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt), sessionId, sk_sig, pk_sig)
        val pi: Pi = vrf.vrfProof(sk_vrf, eta ++ serialize(slot) ++ serialize("NONCE"))
        val rho: Rho = vrf.vrfProofToHash(pi)
        val h: Hash = hash(pb)
        val ledger = blockBox::chooseLedger(pkw)
        val cert: Cert = (pk_vrf, y, pi_y, pk_sig, threshold,blockInfo)
        val sig: KesSignature = kes.sign(sk_kes,h.data++serialize(ledger)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps))
        (h, ledger, slot, cert, rho, pi, sig, pk_kes,bn,ps)
      }
      if (holderIndex == sharedData.printingHolder && printFlag) {
        println("Holder " + holderIndex.toString + " is slot a leader")
      }
    } else {
      roundBlock = -1
    }
    roundBlock match {
      case b: Block => {
        val hb = hash(b)
        blocks.update(localSlot, blocks(localSlot) + (hb -> b))
        localChain.update(localSlot, (localSlot, hb))
        chainHistory.update(localSlot,(localSlot, hb)::chainHistory(localSlot))
        send(self,gossipers, SendBlock(signBox((b,(localSlot, hb)), sessionId, sk_sig, pk_sig)))
        blocksForged += 1
        localState = updateLocalState(localState, Array(localChain(localSlot)))
        issueState = localState
      }
      case _ =>
    }
  }

//  def buildTines:Unit = {
//    for (job <- ListMap(tines.toSeq.sortBy(_._1):_*)) {
//      buildTine(job)
//    }
//  }

  def buildTine(job:(Int,(Chain,Int,Int,Int,ActorRef))): Unit = {
    val entry = job._2
    var foundAncestor = true
    var tine:Chain = entry._1
    var counter:Int = entry._2
    val previousLen:Int = entry._3
    val totalTries:Int = entry._4
    val ref:ActorRef = entry._5
    var prefix:Slot = 0
    breakable{
      while(foundAncestor) {
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
            foundAncestor = false
          }
        }
      }
    }
    if (foundAncestor) {
      var prevId = localChain(prefix)
      for (id<-tine) {
        getParentId(id) match {
          case pb:BlockId => {
            if (pb == prevId) {
              prevId = id
            } else {
              println("error:pid mismatch in tine building")
              sharedData.throwError
            }
          }
          case _ => {
            println("error:parent block not found")
            sharedData.throwError
          }
        }
      }
      candidateTines = Array((tine,prefix)) ++ candidateTines
      tines -= job._1
    } else {
      if (counter>2*tineMaxTries) {
        if (holderIndex == sharedData.printingHolder && printFlag) println("Holder " + holderIndex.toString + " Dropping Old Tine")
        tines -= job._1
      } else {
        tines -= job._1
        tines += (job._1 -> (tine,counter,tine.length,totalTries+1,ref))
        if (totalTries > tineMaxTries) {
          if (holderIndex == sharedData.printingHolder && printFlag) println(
            "Holder " + holderIndex.toString + " Looking for Parent Blocks C:"+counter.toString+"L:"+tine.length
          )
          val depth:Int = if (totalTries - tineMaxTries < tineMaxDepth) {
            totalTries - tineMaxTries
          } else {
            tineMaxDepth
          }
          val request:ChainRequest = (tine.head,depth,job._1)
          send(self,ref, RequestChain(signBox(request,sessionId,sk_sig,pk_sig)))
        } else {
          if (holderIndex == sharedData.printingHolder && printFlag) println("Holder " + holderIndex.toString + " Looking for Parent Block C:"+counter.toString+"L:"+tine.length)
          val request:BlockRequest = (tine.head,job._1)
          send(self,ref, RequestBlock(signBox(request,sessionId,sk_sig,pk_sig)))
        }
      }
    }
  }

  /**main chain selection routine, maxvalid-bg*/
  def maxValidBG = {
    val prefix:Slot = candidateTines.last._2
    val tine:Chain = expand(candidateTines.last._1,prefix)
    var trueChain = false
    val s1 = tine.last._1
    val bnt = {getBlock(tine.last) match {case b:Block => b._9}}
    val bnl = {getBlock(localChain(lastActiveSlot(localChain,localSlot))) match {case b:Block => b._9}}
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
      if (holderIndex == sharedData.printingHolder && printFlag) println("Holder " + holderIndex.toString + " Adopting Chain")
      collectLedger(subChain(localChain,prefix+1,localSlot))
      collectLedger(tine)

      for (i <- prefix+1 to localSlot) {
        localChain.update(i,(-1,ByteArrayWrapper(Array())))
        chainHistory.update(i,(-1,ByteArrayWrapper(Array()))::chainHistory(i))
      }
      for (id <- tine) {
        if (id._1 > -1) {
          localChain.update(id._1,id)
          chainHistory.update(id._1,id::{chainHistory(id._1).tail})
          getBlock(id) match {
            case b:Block => {
              val blockState = b._2
              for (entry<-blockState.tail) {
                entry match {
                  case trans:Transaction => {
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
      eta = history_eta(prefix/epochLength)
      localSlot = prefix
      currentEpoch = localSlot/epochLength
    } else {
      collectLedger(tine)
      for (id <- subChain(localChain,prefix+1,localSlot)) {
        if (id._1 > -1) {
          getBlock(id) match {
            case b: Block => {
              val blockState = b._2
              for (entry <- blockState.tail) {
                entry match {
                  case trans: Transaction =>  {
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
    candidateTines = candidateTines.dropRight(1)
  }

  /**slot routine, called every time currentSlot increments*/
  def updateSlot = {
    time(
      updateEpoch
    )
    if (localSlot == globalSlot) {
      time(
        if (kes.getKeyTimeStep(sk_kes) < localSlot) {
          if (holderIndex == sharedData.printingHolder && printFlag && localSlot%epochLength == 0) {
            println("Current Epoch = " + currentEpoch.toString)
            println("Holder " + holderIndex.toString + " alpha = " + alpha.toString+"\nEta:"+Base58.encode(eta))
          }
          roundBlock = 0
          if (holderIndex == sharedData.printingHolder) println("Slot = " + localSlot.toString + " Last Bid = " + Base58.encode(localChain(lastActiveSlot(localChain,globalSlot))._2.data))
          if (holderIndex == sharedData.printingHolder && printFlag) {
            println("Holder " + holderIndex.toString + " Update KES")
          }
          sk_kes = kes.updateKey(sk_kes, localSlot)
          if (useGossipProtocol) {
            val newOff = (numGossipers*math.sin(2.0*math.Pi*(globalSlot.toDouble/k_s.toDouble+phase))/2.0).toInt
            if (newOff != gOff) {
              if (gOff < newOff) numHello = 0
              gOff = newOff
            }
            if (gossipers.length < numGossipers + gOff && numHello < 1) {
              send(self,rng.shuffle(holders.filter(_!=self)),Hello(signBox(self, sessionId, sk_sig, pk_sig)))
              numHello += 1
            } else if (gossipers.length > numGossipers + gOff) {
              gossipers = rng.shuffle(gossipers).take(numGossipers + gOff)
            }
          }
        }
      )
    }
    localState = updateLocalState(localState, Array(localChain(localSlot)))
    issueState = localState
    if (dataOutFlag && globalSlot % dataOutInterval == 0) {
      coordinatorRef ! WriteFile
    }
  }

  /**epoch routine, called every time currentEpoch increments*/
  def updateEpoch = {
    if (localSlot / epochLength > currentEpoch) {
      currentEpoch = localSlot / epochLength
      stakingState = {
        if (currentEpoch > 1) {history_state((currentEpoch-1)*epochLength)} else {history_state(0)}
      }
      alpha = relativeStake((pk_sig, pk_vrf, pk_kes), stakingState)
      netStake = {
        var net:BigInt = 0
        for (entry<-stakingState) {
          net += entry._2._1
        }
        net
      }
      if (currentEpoch == 0) netStake0 = netStake
      threshold = phi(alpha, f_s)
      if (currentEpoch > 0) {
        eta = eta(localChain, currentEpoch, history_eta(currentEpoch-1))
        history_eta.update(currentEpoch,eta)
      }
    }
  }

  def update = { if (sharedData.error) {actorStalled = true}
    if (!actorStalled) {
      if (!updating) {
        updating = true
        if (globalSlot > tMax || sharedData.killFlag) {
          timers.cancelAll
        } else if (diffuseSent) {
          if (!useFencing) coordinatorRef ! GetTime
          if (globalSlot > localSlot) {
            while (globalSlot > localSlot) {
              history_state.update(localSlot, localState)
              localSlot += 1
              updateSlot
            }
          } else if (roundBlock == 0 && candidateTines.isEmpty) {
            if (holderIndex == sharedData.printingHolder && printFlag) {println("Holder " + holderIndex.toString + " Forging")}
            forgeBlock
            if (useFencing) {routerRef ! (self,"updateSlot")}
          } else if (!useFencing && candidateTines.nonEmpty) {
            if (holderIndex == sharedData.printingHolder && printFlag) {
              println("Holder " + holderIndex.toString + " Checking Tine")
            }
            time(maxValidBG)
          } else if (useFencing && chainUpdateLock) {
            if (candidateTines.isEmpty) {
              chainUpdateLock = false
            } else {
              if (holderIndex == sharedData.printingHolder && printFlag) {
                println("Holder " + holderIndex.toString + " Checking Tine")
              }
              time(maxValidBG)
            }
          }
        }
        updating = false
      }
    }
  }

  def receive: Receive = {

/**************************************************** Holders *********************************************************/

      /**updates time, the kes key, and resets variables */
    case Update => {
      update
    }

    case value:GetSlot => {
      if (!actorStalled) {
        globalSlot += 1
        assert(globalSlot == value.s)
        while (roundBlock == 0) {
          update
        }
      } else {
        if (useFencing) {routerRef ! (self,"updateSlot")}
      }
      sender() ! "done"
    }

    case "updateChain" => if (useFencing) {
      if (!actorStalled) {
        chainUpdateLock = true
        while (chainUpdateLock) {
          update
        }
        routerRef ! (self,"updateChain")
      } else {
        routerRef ! (self,"updateChain")
      }
    }

    case "endStep" => if (useFencing) {
      roundBlock = 0
      routerRef ! (self,"endStep")
    }

    case "passData" => if (useFencing) {
      routerRef ! (self,"passData")
    }

      /**adds confirmed transactions to buffer and sends new ones to gossipers*/
    case value:SendTx => {
      if (!actorStalled) {
        value.s match {
          case trans:Transaction => {
            if (!memPool.keySet.contains(trans._4) && localState.keySet.contains(trans._1)) {
              val delta:BigInt = trans._3
              val pk_s:PublicKeyW = trans._1
              val net = localState(pk_s)._1
              if (delta<=net && localState(pk_s)._3 <= trans._5) {
                if (verifyTransaction(trans)) {
                  memPool += (trans._4->trans)
                  send(self,gossipers, SendTx(value.s))
                }
              }
            }
          }
          case _ =>
        }
      }
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }

      /**block passing, new blocks delivered are added to list of tines and then sent to gossipers*/
    case value:SendBlock => {
      if (!actorStalled) {
        value.s match {
          case s:Box => if (inbox.keySet.contains(s._2)) {
            s._1 match {
              case bInfo: (Block,BlockId) => {
                val bid:BlockId = bInfo._2
                val foundBlock = blocks(bid._1).contains(bid._2)
                if (!foundBlock) {
                  val b:Block = bInfo._1
                  val bHash = hash(b)
                  val bSlot = b._3
                  if (verifyBox(s) && verifyBlock(b) && bHash == bid._2 && bSlot == bid._1) {
                    if (!foundBlock) blocks.update(bSlot, blocks(bSlot) + (bHash -> b))
                    if (!foundBlock && bSlot <= globalSlot) {
                      if (holderIndex == sharedData.printingHolder && printFlag) {
                        println("Holder " + holderIndex.toString + " Got New Tine")
                      }
                      val newId = (bSlot, bHash)
                      send(self,gossipers, SendBlock(signBox((b,newId), sessionId, sk_sig, pk_sig)))
                      val jobNumber = tineCounter
                      tines += (jobNumber -> (Array(newId),0,0,0,inbox(s._2)._1))
                      buildTine((jobNumber,tines(jobNumber)))
                      tineCounter += 1
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
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }

      /**block passing, returned blocks are added to block database*/
    case value:ReturnBlock => {
      if (!actorStalled) {
        value.s match {
          case s:Box => if (inbox.keySet.contains(s._2)) {
            s._1 match {
              case returnedBlocks: (Int,List[(Block,BlockId)]) => {
                if (holderIndex == sharedData.printingHolder && printFlag) {
                  println("Holder " + holderIndex.toString + " Got Blocks")
                }
                val jobNumber:Int = returnedBlocks._1
                val bList = returnedBlocks._2
                for (bInfo <- bList) {
                  val bid:BlockId = bInfo._2
                  val foundBlock = blocks(bid._1).contains(bid._2)
                  if (!foundBlock) {
                    val b:Block = bInfo._1
                    val bHash = hash(b)
                    val bSlot = b._3
                    if (verifyBox(s) && verifyBlock(b) && bHash == bid._2 && bSlot == bid._1) {
                      blocks.update(bSlot, blocks(bSlot) + (bHash -> b))
                    }
                  }
                }
                if (tines.keySet.contains(jobNumber)) buildTine((jobNumber,tines(jobNumber)))
              }
              case nullBlock:NullBlock => {
                val jobNumber = nullBlock.job
                if (tines.keySet.contains(jobNumber)) buildTine((jobNumber,tines(jobNumber)))
              }
              case _ =>
            }
          }
          case _ =>
        }
      }
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }

      /**block passing, parent ids that are not found are requested*/
    case value:RequestBlock => {
      if (!actorStalled) {
        value.s match {
          case s:Box => {
            if (inbox.keySet.contains(s._2)) {
              if (holderIndex == sharedData.printingHolder && printFlag) {
                println("Holder " + holderIndex.toString + " Was Requested Block")
              }
              val ref = inbox(s._2)._1
              s._1 match {
                case request:BlockRequest => {
                  val id:BlockId = request._1
                  val job:Int = request._2
                  if (blocks(id._1).contains(id._2)) {
                    if (verifyBox(s)) {
                      val returnedBlock = blocks(id._1)(id._2)
                      send(self,ref,ReturnBlock(signBox((job,List((returnedBlock,id))),sessionId,sk_sig,pk_sig)))
                      if (holderIndex == sharedData.printingHolder && printFlag) {
                        println("Holder " + holderIndex.toString + " Returned Block")
                      }
                    }
                  } else {
                    send(self,ref,ReturnBlock(signBox(NullBlock(job),sessionId,sk_sig,pk_sig)))
                  }
                }
                case _ =>
              }
            }
          }
          case _ =>
        }
      }
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }

      /**block passing, parent ids are requested with increasing depth of chain upto a finite number of attempts*/
    case value:RequestChain => {
      if (!actorStalled) {
        value.s match {
          case s:Box => {
            if (inbox.keySet.contains(s._2)) {
              if (holderIndex == sharedData.printingHolder && printFlag) {
                println("Holder " + holderIndex.toString + " Was Requested Blocks")
              }
              val ref = inbox(s._2)._1
              s._1 match {
                case request:ChainRequest => {
                  val startId:BlockId = request._1
                  val depth:Int = request._2
                  val job:Int = request._3
                  var parentFound = blocks(startId._1).contains(startId._2)
                  var returnedBlockList:List[(Block,BlockId)] = List()
                  if (depth <= tineMaxDepth && parentFound) {
                    if (verifyBox(s)) {
                      var id = startId
                      while (parentFound && returnedBlockList.length < k_s*depth) {
                        parentFound = getBlock(id) match {
                          case b:Block => {
                            returnedBlockList ::= (b,id)
                            id = getParentId(b)
                            true
                          }
                          case _ => false
                        }
                      }
                      if (holderIndex == sharedData.printingHolder && printFlag) {
                        println("Holder " + holderIndex.toString + " Returned Blocks")
                      }
                    }
                  }
                  if (returnedBlockList.nonEmpty) {
                    send(self,ref,ReturnBlock(signBox((job,returnedBlockList),sessionId,sk_sig,pk_sig)))
                  } else {
                    send(self,ref,ReturnBlock(signBox(NullBlock(job),sessionId,sk_sig,pk_sig)))
                  }
                }
                case _ =>
              }
            }
          }
          case _ =>
        }
      }
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }

      /**issue a transaction generated by the coordinator and send it to the list of gossipers*/
    case value:IssueTx => {
      if (!actorStalled) {
        value.s match {
          case data:(PublicKeyW,BigInt) => if (issueState.keySet.contains(pkw)) {
            val (pk_r,delta) = data
            val scaledDelta = BigDecimal(delta.toDouble*netStake.toDouble/netStake0.toDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
            val net = issueState(pkw)._1
            val txC = txCounter//issueState(pkw)._3
            if (delta <= net) {
              if (holderIndex == sharedData.printingHolder && printFlag) {println(s"Holder $holderIndex Issued Transaction")}
              val trans:Transaction = signTransaction(sk_sig,pkw,pk_r,scaledDelta,txC+1)
              issueState = applyTransaction(issueState,trans,ByteArrayWrapper(Array()))
              txCounter += 1
              setOfTxs += (trans._4->trans._5)
              send(self,gossipers, SendTx(trans))
            }
          }
          case _ =>
        }
      }
      if (useFencing) {
        routerRef ! (self,"issueTx")
        sender() ! "done"
      }
    }

      /**gossip protocol greeting message for populating inbox*/
    case value:Hello => {
      //println(gossipers.length, numGossipers + gOff)
      if (!actorStalled) {
        if (gossipers.length < numGossipers + gOff) {
          value.id match {
            case id:Box => {
              id._1 match {
                case ref:ActorRef => {
                  if (verifyBox(id)) {
                    if (!gossipers.contains(ref) && inbox.keySet.contains(id._2)) {
                      if (holderIndex == sharedData.printingHolder && printFlag) {
                        println("Holder " + holderIndex.toString + " Adding Gossiper")
                      }
                      if (inbox(id._2)._1 == ref) gossipers = gossipers ++ List(ref)
                      send(self,ref,Hello(signBox(self, sessionId, sk_sig, pk_sig)))
                    }
                  }
                }
                case _ =>
              }

            }
            case _ =>
          }
        }
      }
      if (useFencing) {
        routerRef ! (self,"passData")
      }
    }


/************************************************** Diffuse ***********************************************************/

    /**sends holder information for populating inbox*/
    case Diffuse => {
      sendDiffuse(holderId, holders, signBox((self,publicKeys), sessionId, sk_sig, pk_sig))
      sender() ! "done"
    }

    /**validates diffused string from other holders and stores in inbox */
    case value:Box => {
      if (verifyBox(value) && !inbox.keySet.contains(value._2)) {
        val sid = value._2
        value._1 match {
          case d:(ActorRef,PublicKeys) => inbox += (sid->d)
          case _ =>
        }
      }
      sender() ! "done"
    }


/************************************************** Coordinator *******************************************************/

      /**allocate arrays and vars of simulation*/
    case value:Initialize => {
      println("Holder "+holderIndex.toString+" starting...")
      tMax = value.tMax
      blocks = blocks++Array.fill(tMax){Map[ByteArrayWrapper,Block]()}
      localChain = Array((0,genBlockHash))++Array.fill(tMax){(-1,ByteArrayWrapper(Array()))}
      chainHistory = Array(List((0,genBlockHash)))++Array.fill(tMax){List((-1,ByteArrayWrapper(Array())))}
      history_eta = Array.fill(tMax/epochLength+1){Array()}
      history_state = Array.fill(tMax+1){Map()}
      assert(genBlockHash == hash(blocks(0)(genBlockHash)))
      localState = updateLocalState(localState, Array(localChain(0)))
      eta = eta(localChain, 0, Array())
      history_state.update(0,localState)
      history_eta.update(0,eta)
      sender() ! "done"
    }

      /**starts the timer that repeats the update command*/
    case Run => {
      if (!useFencing) timers.startPeriodicTimer(timerKey, Update, updateTime)
    }

      /**sets the initial time*/
    case value:SetClock => {
      t0 = value.t0
      sender() ! "done"
    }

      /**sets the slot from coordinator time*/
    case value:GetTime => if (!actorStalled) {
      globalSlot = ((value.t1 - t0) / slotT).toInt
    }

      /**accepts list of other holders from coordinator */
    case list:List[ActorRef] => {
      holders = list
      if (useGossipProtocol) {
        gossipers = List()
      } else {
        gossipers = gossipSet(holderId,holders)
      }
      var i = 0
      for (holder <- holders) {
        if (self == holder) holderIndex = i
        i += 1
      }
      sender() ! "done"
    }

      /**accepts genesis block from coordinator */
    case gb:GenBlock => {
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

      /**when stalled actor will do nothing when messages are received*/
    case StallActor => {
      if (!actorStalled) {actorStalled = true}
      else {actorStalled = false}
      sender() ! "done"
    }

      /**prints inbox */
    case Inbox => {
      var i = 0
      println("Holder "+holderIndex.toString+":"+Base58.encode(sessionId.data))
      for (entry <- inbox) {
        println(i.toString+" "+Base58.encode(entry._1.data))
        i+=1
      }
      println("")
      sender() ! "done"
    }

      /**prints stats */
    case Verify => {
      val trueChain = verifyChain(localChain, genBlockHash)
      println("Holder "+holderIndex.toString + ": t = " + localSlot.toString + ", alpha = " + alpha.toString + ", blocks forged = "
        + blocksForged.toString + "\nChain length = " + getActiveSlots(localChain).toString + ", Valid chain = "
        + trueChain.toString)
      var chainBytes:Array[Byte] = Array()
      for (id <- subChain(localChain,0,localSlot-confirmationDepth)) {
        getBlock(id) match {
          case b:Block => chainBytes ++= FastCryptographicHash(serialize(b))
          case _ =>
        }
      }
      println("Public Key: "+Base58.encode(pk_sig++pk_vrf++pk_kes))
      println("Path: "+self.path)
      println("Chain hash: " + Base58.encode(FastCryptographicHash(chainBytes))+"\n")
      if (sharedData.error){
        for (id <- localChain) {
          if (id._1 > -1) println("H:" + holderIndex.toString + "S:" + id._1.toString + "ID:" + Base58.encode(id._2.data))
        }
        for (e <- history_eta) {
          if (!e.isEmpty) println("H:" + holderIndex.toString + "E:" + Base58.encode(e))
        }
        println("e:" + Base58.encode(eta(localChain, currentEpoch)) + "\n")
      }
      sender() ! "done"
    }

      /**prints stats */
    case Status => {
      println("Holder "+holderIndex.toString + ": t = " + localSlot.toString + ", alpha = " + alpha.toString + ", blocks forged = "
        + blocksForged.toString + "\nChain length = " + getActiveSlots(localChain).toString+", MemPool Size = "+memPool.size+" Num Gossipers = "+gossipers.length.toString)
      var chainBytes:Array[Byte] = Array()
      for (id <- subChain(localChain,0,localSlot-confirmationDepth)) {
        getBlock(id) match {
          case b:Block => {
            chainBytes ++= FastCryptographicHash(serialize(b))
          }
          case _ =>
        }
      }
      sharedData.txCounter += txCounter
      sharedData.setOfTxs ++= setOfTxs
      var txCount = 0
      var allTx:List[Sid] = List()
      var duplicatesFound = false
      var allTxSlots:List[Slot] = List()
      var holderTxOnChain:List[(Sid,Transaction)] = List()
      for (id <- subChain(localChain,0,localSlot)) {
        getBlock(id) match {
          case b:Block => {
            val state = b._2
            for (entry<-state) {
              entry match {
                case trans:Transaction => {
                  if (!allTx.contains(trans._4)) {
                    if (trans._1 == pkw) holderTxOnChain ::= (trans._4,trans)
                    allTx ::= trans._4
                    allTxSlots ::= b._3
                    txCount+=1
                  } else {
                    duplicatesFound = true
                    val dupIndex = allTx.indexOf(trans._4)
                  }
                }
                case _ =>
              }
            }
          }
          case _ =>
        }
      }
      val holderTxCount = holderTxOnChain.length
      val holderTxCountTotal = setOfTxs.keySet.size
      val txCountChain = if (holderTxOnChain.isEmpty) {0} else {holderTxOnChain.head._2._5}
      val txCountState = math.max(localState(pkw)._3-1,0)
      println(s"Tx Counts in state and chain: $txCountState, $txCountChain")
      println(s"Transactions on chain: $holderTxCount / $holderTxCountTotal Total: $txCount Duplicates: $duplicatesFound")
      println("Chain hash: " + Base58.encode(FastCryptographicHash(chainBytes))+"\n")
      if (false){
        for (id <- localChain) {
          if (id._1 > -1) {
            println("S:" + id._1.toString)
            getBlock(id) match {
              case b:Block => {
                for (entry<-b._2) {
                  entry match {
                    case trans:Transaction => println(Base58.encode(trans._4.data)+":"+trans._3.toString)
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

      /**writes data point to file*/
    case value:WriteFile => if (!actorStalled) {
      value.fw match {
        case fileWriter: BufferedWriter => {
          val fileString = (
            holderIndex.toString + " "
              + globalSlot.toString + " "
              + alpha.toString + " "
              + blocksForged.toString + " "
              + getActiveSlots(localChain).toString + " "
              + "\n"
            )
          fileWriter.write(fileString)
        }
        case _ => println("error: data file writer not initialized")
      }
    }

      /**accepts coordinator ref*/
    case value:CoordRef => {
      value.ref match {
        case r: ActorRef => coordinatorRef = r
        case _ =>
      }
      sender() ! "done"
    }

      /**accepts router ref*/
    case value:RouterRef => {
      value.ref match {
        case r: ActorRef => routerRef = r
        case _ =>
      }
      sender() ! "done"
    }

      /**sets new list of holders resets gossipers*/
    case value:Party => {
      value.list match {
        case list: List[ActorRef] => {
          holders = list
          if (useGossipProtocol) {
            gossipers = List()
            numHello = 0
          } else {
            gossipers = gossipSet(holderId,holders)
          }
          if (value.clear) inbox = Map()
          diffuseSent = false
        }
        case _ =>
      }
      sender() ! "done"
    }

    case RequestGossipers => {
      sender() ! GetGossipers(gossipers)
    }

    case RequestState => {
      sender() ! GetState(stakingState)
    }

    case RequestBlockTree => {
      sender() ! GetBlockTree(blocks,chainHistory)
    }

    case RequestKeys => {
      sender() ! diffuse(bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes), s"{$holderId}", sk_sig)
    }

    case unknown:Any => if (!actorStalled) {
      print("received unknown message ")
      if (sender() == coordinatorRef) {
        print("from coordinator")
      }
      if (sender() == routerRef) {
        print("from router")
      }
      if (holders.contains(sender())) {
        print("from holder "+holders.indexOf(sender()).toString)
      }
      println(": "+unknown.getClass.toString)
    }
  }
}

object Stakeholder {
  def props(seed:Array[Byte]): Props = Props(new Stakeholder(seed))
}

