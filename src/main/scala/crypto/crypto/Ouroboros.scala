package crypto.ouroboros

import akka.actor.{ Actor, ActorSystem, Props }
import akka.event.Logging


object StakeHolder {
  def props: Props = Props(new StakeHolder)
}

class StakeHolder extends Actor {
  def receive: Receive = {
    case value: String => {
      val holderRef = context.actorOf(Props.empty, "stakeholder")
      println(Ouroboros.diffuse(value,s"$holderRef"))
    }
    case _ => println("received unknown message")
  }
}

object Ouroboros {
  def diffuse(str: String,id: String): String = {
    str+":Message from stakeholder "+id
  }
}
