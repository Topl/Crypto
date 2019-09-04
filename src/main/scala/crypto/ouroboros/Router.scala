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
  var holderMessages:Map[Slot,Map[ActorRef,Map[Long,Map[BigInt,(ActorRef,ActorRef,Any)]]]] = Map()
  var holderReady:Map[ActorRef,Boolean] = Map()
  var globalSlot:Slot = 0
  var localSlot:Slot = -1
  var coordinatorRef:ActorRef = _
  var t0:Long = 0
  var roundDone = true
  var firstDataPass = true
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

  def deliver = {
    for (holder<-rng.shuffle(holders)) {
      val slotMessages = holderMessages(globalSlot)
      if (slotMessages.keySet.contains(holder)) {
        val queue = slotMessages(holder)
        for (entry <- ListMap(queue.toSeq.sortBy(_._1):_*)) {
          for (message<-ListMap(entry._2.toSeq.sortBy(_._1):_*)) {
            val (s,r,c) = message._2
            reset(r)
            //println(holders.indexOf(s),holders.indexOf(r),c.getClass,message._1)
            context.system.scheduler.scheduleOnce(0 nano,r,c)(context.system.dispatcher,s)
          }
        }
      }
    }
    holderMessages -= globalSlot
  }

  def update = {
    if (globalSlot > L_s || sharedData.killFlag) {
      timers.cancelAll
    } else {
      if (globalSlot > localSlot && roundDone) {
        roundDone = false
        localSlot = globalSlot
        roundStep = "updateSlot"
        reset
        for (holder<-holders) {
          holder ! GetSlot(globalSlot)
        }
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
              if (holderMessages.keySet.contains(globalSlot)) {
                deliver
              } else {
                roundStep = "updateChain"
                reset
                for (holder<-holders) {
                  holder ! "updateChain"
                }
              }
            } else {
              if (firstDataPass) {
                for (holder<-holders) {
                  holder ! "passData"
                }
                firstDataPass = false
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
            firstDataPass = true
            coordinatorRef ! NextSlot
          }
          case _ =>
        }
      }
    }
  }

  def receive: Receive = {

    case flag:(ActorRef,String) => {
      val (ref,value) = flag
//      if (value == "updateChain" || value == "passData") {println(value+" "+holders.indexOf(sender).toString)
//        for (holder<-holders) {
//          println(holders.indexOf(holder).toString+" "+holderReady(holder))
//        }
//        println(holderMessages.keySet.contains(globalSlot))
//      }
      if (value == roundStep && holderReady.keySet.contains(ref)) {
        holderReady -= ref
        holderReady += (ref -> true)
      }
    }


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

    case NextSlot => {
      globalSlot += 1
    }

    /** adds delay to routed message*/
    case newMessage:(ActorRef,ActorRef,Any) => {
      val (s,r,c) = newMessage
      context.system.scheduler.scheduleOnce(delay(s,r),r,c)(context.system.dispatcher,sender())
    }

    case newIdMessage:(BigInt,ActorRef,ActorRef,Any) => {
      val (uid,s,r,c) = newIdMessage
      val newMessage = (s,r,c)
      val nsDelay = delay(s,r)
      val messageDelta:Slot = (nsDelay.toNanos/(slotT*1000000)).toInt
      val priority:Long = nsDelay.toNanos%(slotT*1000000)
      val offsetSlot = globalSlot+messageDelta
      val messages:Map[ActorRef,Map[Long,Map[BigInt,(ActorRef,ActorRef,Any)]]] = if (holderMessages.keySet.contains(offsetSlot)) {
        var m = holderMessages(offsetSlot)
        holderMessages -= offsetSlot
        if (m.keySet.contains(s)) {
          var l = m(s)
          m -= s
          if (l.keySet.contains(priority)) {
            var q = l(priority)
            l -= priority
            q += (uid -> newMessage)
            l += (priority -> q)
          } else {
            l += (priority -> Map(uid->newMessage))
          }
          m += (s -> l)
          m
        } else {
          m += (s -> Map(priority -> Map(uid -> newMessage)))
          m
        }
      } else {
        Map(s -> Map(priority -> Map(uid -> newMessage)))
      }
      holderMessages += (offsetSlot-> messages)
    }

    case Run => {
      timers.startPeriodicTimer(timerKey, Update, updateTime)
      coordinatorRef ! NextSlot
    }

    case value:CoordRef => {
      value.ref match {
        case r: ActorRef => coordinatorRef = r
        case _ =>
      }
      sender() ! "done"
    }

    case value:String => if (value == "fence_step") println(roundStep)

    case Update => update

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