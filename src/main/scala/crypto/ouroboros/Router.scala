package crypto.ouroboros

import akka.actor.{Actor, ActorRef, Props, Timers}

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
  var holderMessages:Map[Int,Map[ActorRef,List[(ActorRef,ActorRef,Any)]]] = Map()
  var holderReady:Map[ActorRef,Boolean] = Map()
  var globalSlot:Slot = -1
  var localSlot:Slot = -1
  var coordinatorRef:ActorRef = _
  var t0:Long = 0
  var roundDone = true
  var roundStep = ""

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
    case value:(ActorRef,ActorRef,Any) => if (useFencing) {
      //process message here
    } else {
      val (s,r,c) = value
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
              if (holdersReady) {
                roundStep = "updateChain"
                reset
              }
            }
            case "updateChain" => {
              if (holdersReady) {
                roundStep = "endStep"
                reset
              }
            }
            case "endStep" => if (holdersReady) {
              roundDone = true
              reset
            }
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