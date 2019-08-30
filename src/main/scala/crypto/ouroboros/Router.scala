package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import scala.collection.immutable.ListMap
import scala.math.BigInt
import scala.util.Random
import scala.concurrent.duration._


class Router(seed:Array[Byte]) extends Actor
  with Parameters
  with Types
  with Timers {
  var holders:List[ActorRef] = List()
  val rng = new Random(BigInt(seed).toLong)
  var holdersPosition:Map[ActorRef,(Double,Double)] = Map()
  var distanceMap:Map[(ActorRef,ActorRef),Long] = Map()
  var holderMessages:Map[Slot,Map[ActorRef,Map[Long,List[(ActorRef,ActorRef,Any)]]]] = Map()
  var holderReady:Map[ActorRef,Boolean] = Map()
  var globalSlot:Slot = -1
  var localSlot:Slot = -1
  var coordinatorRef:ActorRef = _
  var t0:Long = 0
  var roundDone = true
  var roundStep = "updateSlot"

  private case object timerKey

  def holdersReady:Boolean = {
    var bool = true
    for (holder <- holders){
      bool &&= holderReady(holder)
    }
    bool
  }

  def reset:Unit = {
    for (holder <- holders){
      if (holderReady.keySet.contains(holder)) holderReady -= holder
      holderReady += (holder->false)
    }
  }

  def reset(holder:ActorRef):Unit = {
    if (holderReady.keySet.contains(holder)) holderReady -= holder
    holderReady += (holder->false)
  }

  def delay(sender:ActorRef,recip:ActorRef):FiniteDuration = {
    if (!distanceMap.keySet.contains((sender,recip))) {
      distanceMap += ((sender,recip)->(delay_ms_km*1.0e6*DistanceCalculator.distance(
        holdersPosition(sender)._1,
        holdersPosition(sender)._2,
        holdersPosition(recip)._1,
        holdersPosition(recip)._2,
        "K")).toLong)
    }
    distanceMap((sender,recip)).nano
  }

  def receive: Receive = {
    /** accepts list of other holders from coordinator */
    case list:List[ActorRef] => {
      holders = list
      for (holder<-holders) {
        if (!holdersPosition.keySet.contains(holder)) {
          holdersPosition += (holder->(rng.nextDouble()*180.0-90.0,rng.nextDouble()*360.0-180.0))
        }
      }
      if (useFencing) {
        for (holder<-holders) {
          if (!holderReady.keySet.contains(holder)) {
            holderReady += (holder->false)
          }
        }
      }
      sender() ! "done"
    }

    /** adds delay to routed message*/
    case newMessage:(ActorRef,ActorRef,Any) => if (useFencing) {
      val (s,r,_) = newMessage
      val nsDelay = delay(s,r)
      val messageDelta:Slot = (nsDelay.toMillis/slotT).toInt
      val priority:Long = nsDelay.toNanos%(slotT*1000000)
      val offsetSlot = globalSlot+messageDelta
      val messages:Map[ActorRef,Map[Long,List[(ActorRef,ActorRef,Any)]]] = if (holderMessages.keySet.contains(offsetSlot)) {
        var m = holderMessages(offsetSlot)
        holderMessages -= offsetSlot
        if (m.keySet.contains(s)) {
          var l = m(s)
          m -= s
          if (l.keySet.contains(priority)) {
            var q = l(priority)
            l -= priority
            q ::= newMessage
            l += (priority -> q)
          } else {
            l += (priority -> List(newMessage))
          }
          m += (s -> l)
          m
        } else {
          m += (s -> Map(priority -> List(newMessage)))
          m
        }
      } else {
        Map(s -> Map(priority -> List(newMessage)))
      }
      holderMessages += (offsetSlot-> messages)
    } else {
      val (s,r,c) = newMessage
      context.system.scheduler.scheduleOnce(delay(s,r),r,c)(context.system.dispatcher,sender())
    }

    case Run => {
      timers.startPeriodicTimer(timerKey, Update, updateTime)
    }

    case value:CoordRef => {
      value.ref match {
        case r: ActorRef => coordinatorRef = r
        case _ =>
      }
      sender() ! "done"
    }

    case value:String => {
      if (value == roundStep && holderReady.keySet.contains(sender())) {
        holderReady -= sender()
        holderReady += (sender() -> true)
      }
      if (value == "fence_step") println(roundStep)
    }

    case Update => {
      if (globalSlot > L_s || sharedData.killFlag) {
        timers.cancelAll
      } else {
        coordinatorRef ! GetTime
        if (globalSlot > localSlot) {
          coordinatorRef ! StallActor
          roundDone = false
          localSlot = globalSlot
          roundStep = "updateSlot"
        } else {
          roundStep match {
            case "updateSlot" => {
              if (holdersReady) {
                roundStep = "issueTx"
                coordinatorRef ! IssueTx("randTx")
                reset
              }
            }
            case "issueTx" => {
              if (holdersReady) {
                roundStep = "passData"
                reset
              }
            }
            case "passData" => {
              if (holdersReady && !holderMessages.keySet.contains(globalSlot)) {
                roundStep = "updateChain"
                for (holder<-holders) {
                  holder ! "updateChain"
                }
                reset
              } else {
                if (holderMessages.keySet.contains(globalSlot)) {
                  val slotMessages = holderMessages(globalSlot)
                  for (holder<-rng.shuffle(holders)) {
                    if (slotMessages.keySet.contains(holder)) {
                      reset(holder)
                      val queue = slotMessages(holder)
                      for (entry <- ListMap(queue.toSeq.sortBy(_._1):_*)) {
                        if (entry._2.length > 1) {
                          var mMap:Map[BigInt,(ActorRef,ActorRef,Any)] = Map()
                          var mList:List[(ActorRef,ActorRef,Any)] = List()
                          for (m<-entry._2){
                            m._3 match {
                              case value:SendTx => {
                                value.s match {
                                  case trans:Transaction => {
                                    val nid = BigInt(FastCryptographicHash(serialize(trans)))
                                    if (!mMap.keySet.contains(nid)) {
                                      mMap += (nid -> m)
                                    } else {
                                      println("router error: duplicate message")
                                    }
                                  }
                                  case _ =>
                                }
                              }
                              case value:SendBlock => {
                                value.s match {
                                  case s:Box => {
                                    s._1 match {
                                      case bInfo: (Block,BlockId) => {
                                        val b:Block = bInfo._1
                                        val bid:BlockId = bInfo._2
                                        val nid = BigInt(FastCryptographicHash(serialize(b)++serialize(bid)))
                                        if (!mMap.keySet.contains(nid)) {
                                          mMap += (nid -> m)
                                        } else {
                                          println("router error: duplicate message")
                                        }
                                      }
                                      case _ =>
                                    }
                                  }
                                  case _ =>
                                }
                              }
                              case _ => mList ::= m
                            }
                          }
                          for (m<-ListMap(mMap.toSeq.sortBy(_._1):_*)) {
                            val (s,r,c) = entry._2.head
                            context.system.scheduler.scheduleOnce(0 nano,r,c)(context.system.dispatcher,s)
                          }
                          for (m<-mList) {
                            val (s,r,c) = entry._2.head
                            context.system.scheduler.scheduleOnce(0 nano,r,c)(context.system.dispatcher,s)
                          }
                        } else {
                          val (s,r,c) = entry._2.head
                          context.system.scheduler.scheduleOnce(0 nano,r,c)(context.system.dispatcher,s)
                        }
                      }
                    } else {
                      holder ! "passData"
                    }
                  }
                  holderMessages -= globalSlot
                } else {
                  for (holder <- holders) {
                    holder ! "passData"
                  }
                }
              }
            }
            case "updateChain" => {
              if (holdersReady) {
                roundStep = "endStep"
                reset
                for (holder<-holders) {
                  holder ! "endStep"
                }
              }
            }
            case "endStep" => if (holdersReady) {
              roundDone = true
              reset
            }
            case _ =>
          }
        }
        if (roundDone) {coordinatorRef !  StallActor}
      }
    }

    case value:SetClock => {
      t0 = value.t0
      sender() ! "done"
    }

    case value:GetTime => {
      globalSlot = ((value.t1 - t0) / slotT).toInt
    }

    case _ =>
  }
}

object Router {
  def props(seed:Array[Byte]): Props = Props(new Router(seed))
}