package crypto.ouroboros

import java.io.{BufferedWriter, FileWriter}
import java.io.{File, FileNotFoundException}

import akka.actor.{Actor, ActorRef, PoisonPill, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import scala.sys.process._

/**
  * Coordinator actor that initializes the genesis block and instantiates the staking party,
  * sends messages to participants to execute a round
  */
class Coordinator extends Actor
  with Timers
  with obMethods
  with coordinatorVars {
  val coordId = s"${self.path}"
  private case object timerKey

  def receive: Receive = {
    /**populates the holder list with stakeholder actor refs
      * This is the F_init functionality */
    case value: Populate => {
      println("Populating")
      var i = -1
      holders = List.fill(value.n){
        i+=1
        if (randomFlag) {
          context.actorOf(Stakeholder.props(FastCryptographicHash(Array(i.toByte))), "Holder:" + i.toString)
        } else {
          context.actorOf(Stakeholder.props(FastCryptographicHash(uuid)), "Holder:" + i.toString)
        }
      }
      println("Sending holders list")
      send(holders,holders)
      println("Sending holders coordinator ref")
      send(holders,CoordRef(self))
      println("Getting holder keys")
      genKeys = send(holders,GetGenKeys,genKeys)
      assert(!containsDuplicates(genKeys))
      println("Forge Genesis Block")
      val genBlock:Block = forgeGenBlock
      println("Send GenBlock")
      send(holders,GenBlock(genBlock))
    }
    /**tells actors to print their inbox */
    case Inbox => send(holders,Inbox)

    case value:Run => {
      println("starting")
      val t0 = System.currentTimeMillis()
      send(holders,StartTime(t0))
      send(holders,Run(value.max))
      timers.startPeriodicTimer(timerKey, ReadCommand, commandUpdateTime)
    }

    case GetTime => {
      val t1 = System.currentTimeMillis()
      sender() ! GetTime(t1)
    }

    //tells actors to print status */
    case Status => {
      send(holders,Status)
    }

    case value:NewDataFile => {
      if(dataOutFlag) {
        fileWriter = new BufferedWriter(new FileWriter(value.name))
        val fileString = (
          "Holder_number"
            + " t"
            + " alpha"
            + " blocks_forged"
            + " chain_length"
            +" \n"
          )
        fileWriter match {
          case fw: BufferedWriter => {fw.write(fileString)}
          case _ => println("error: file writer not initialized")
        }
      }
    }

    case WriteFile => {
      sender() ! WriteFile(fileWriter)
    }

    case CloseDataFile => if(dataOutFlag) {
      fileWriter match {
        case fw:BufferedWriter => fw.close()
        case _ => println("error: file writer close on non writer object")
      }
    }

    case ReadCommand => {
      if (new File("/tmp/scorex/test-data/crypto/cmd").exists) {
        val f = new File("/tmp/scorex/test-data/crypto/cmd")
        val cmd: String = ("cat" #< f).!!
        f.delete
        command(cmd)
      }
    }

    case _ => println("received unknown message")
  }

  def command(s:String): Unit = {
    s.trim match {
      case "status" => self ! Status
      case "pause" => send(holders,StallActor)
      case "inbox" => send(holders,Inbox)
      case "stall0" => send(holders(0),StallActor)
      case "kill" => {
        send(holders,StallActor)
        for (holder<-holders){ holder ! PoisonPill}
        sharedFlags.killFlag = true
        self ! CloseDataFile
        context.system.terminate
      }
      case _ =>
    }
  }

  /**creates genesis block to be sent to all stakeholders */
  def forgeGenBlock: Block = {
    val bn:Int = 0
    val ps:Slot = -1
    val slot:Slot = t
    val pi:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = vrf.vrfProofToHash(pi)
    val pi_y:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = vrf.vrfProofToHash(pi_y)
    val h:Hash = ByteArrayWrapper(eta0)
    val r = scala.util.Random
    // set initial stake distribution, set to random value between 0.0 and initStakeMax for each stakeholder
    val state: State = holders.map{ case ref:ActorRef => {
      val initStake = {
        if (randomFlag) {
          initStakeMax*r.nextDouble
        } else {
          initStakeMax
        }
      }
      signTx(
        genesisBytes
          ++hex2bytes(genKeys(s"${ref.path}").split(";")(0))
          ++hex2bytes(genKeys(s"${ref.path}").split(";")(1))
          ++hex2bytes(genKeys(s"${ref.path}").split(";")(2)),
        serialize(coordId),sk_sig,pk_sig) -> BigDecimal(initStake).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
    }}.toMap
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,1.0)
    val sig:MalkinSignature = kes.sign(malkinKey, h.data++serialize(state)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps))
    (h,state,slot,cert,rho,pi,sig,pk_kes,bn,ps)
  }
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}