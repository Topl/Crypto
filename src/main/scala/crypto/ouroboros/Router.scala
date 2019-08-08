package crypto.ouroboros

import akka.actor.{Actor, ActorRef, PoisonPill, Props, Timers}

import scala.math.BigInt
import scala.util.Random
import scala.concurrent.duration._


class Router(seed:Array[Byte]) extends Actor with Parameters {
  var holders:List[ActorRef] = List()
  val rng = new Random(BigInt(seed).toLong)
  var holdersPosition:Map[ActorRef,(Double,Double)] = Map()
  var distanceMap:Map[(ActorRef,ActorRef),Long] = Map()

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
      sender() ! "done"
    }

    /** adds delay to routed message*/
    case value:(ActorRef,ActorRef,Any) => {
      val (s,r,c) = value
      context.system.scheduler.scheduleOnce(delay(s,r),r,c)(context.system.dispatcher,sender())
    }
    case _ =>
  }
}

object Router {
  def props(seed:Array[Byte]): Props = Props(new Router(seed))
}