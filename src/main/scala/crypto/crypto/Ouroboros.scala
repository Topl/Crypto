package crypto.ouroboros

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.event.Logging


object StakeHolder {
  def props: Props = Props(new StakeHolder)
}

case object Diffuse
case object Receive
case object Inbox

class StakeHolder extends Actor {
  var inbox:String = ""
  var holders: List[ActorRef] = List()
  var diffuseSent = false
  var holderId = s"${self.path}"
  var stake = 0.0

  def receive: Receive = {
    case value: String => {
      inbox = inbox+value
    }
    case list: List[ActorRef] => {
      holders = list
    }
    case Diffuse => {
      if (!diffuseSent) {
        diffuseSent = true
        for (holder <- holders) {
          holder ! diffuse("data",holderId)
        }
      }
    }
    case Inbox => println(inbox);println()
    case _ => println("received unknown message")
  }
  def diffuse(str: String,id: String): String = {
    str+" from "+id+"\n"
  }
}

object Ouroboros {

}
