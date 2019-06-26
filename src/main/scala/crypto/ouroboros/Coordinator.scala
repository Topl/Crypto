package crypto.ouroboros

import java.io.{BufferedWriter, FileWriter}
import akka.actor.{Actor, ActorRef, Props, Timers}

/**
  * Coordinator actor that initializes the genesis block and instantiates the staking party,
  * sends messages to participants to execute a round
  */
class Coordinator extends Actor
  with Timers
  with obMethods
  with coordinatorVars {
  val coordId = s"${self.path}"
  def receive: Receive = {
    /**populates the holder list with stakeholder actor refs
      * This is the F_init functionality */
    case value: Populate => {
      holders = List.fill(value.n){
        context.actorOf(Stakeholder.props, "holder:" + uuid)
      }
      send(holders,holders)
      send(holders,CoordRef(self))
      genKeys = send(holders,GetGenKeys,genKeys)
      assert(!containsDuplicates(genKeys))
      val genBlock:Block = forgeGenBlock
      send(holders,GenBlock(genBlock))
    }
    /**tells actors to print their inbox */
    case Inbox => send(holders,Inbox)

    case value:Run => {
      println("starting")
      val t0 = System.currentTimeMillis()
      send(holders,StartTime(t0))
      send(holders,Run(value.max))
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
            + " chain_hash"
            +"\n"
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
    case _ => println("received unknown message")
  }
  /**creates genesis block to be sent to all stakeholders */
  def forgeGenBlock: Block = {
    val slot:Slot = t
    val pi:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = vrf.vrfProofToHash(pi)
    val pi_y:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = vrf.vrfProofToHash(pi_y)
    val hash:Hash = eta0
    val r = scala.util.Random
    // set initial stake distribution, set to random value between 0.0 and initStakeMax for each stakeholder
    val state: State = holders.map{ case ref:ActorRef => signTx(
      genesisBytes
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(0))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(1))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(2)),
      serialize(coordId),sk_sig,pk_sig) -> BigDecimal(initStakeMax * r.nextDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt}.toMap
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,1.0)
    val sig:MalkinSignature = kes.sign(malkinKey, hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi)
    (hash,state,slot,cert,rho,pi,sig,pk_kes)
  }
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}
