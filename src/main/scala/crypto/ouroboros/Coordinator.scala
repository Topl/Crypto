package crypto.ouroboros

import java.io.{BufferedWriter, FileWriter}
import akka.actor.{Actor, ActorRef, Props}
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.MalkinSignature
import scala.util.Random

/**
  * Coordinator actor that initializes the genesis block and instantiates the staking party,
  * sends messages to participants to execute a round
  */
class Coordinator extends Actor
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
      genKeys = send(holders,GetGenKeys,genKeys)
      assert(!containsDuplicates(genKeys))
      val genBlock:Block = forgeGenBlock
      send(holders,GenBlock(genBlock))
    }
    /**tells actors to print their inbox */
    case Inbox => send(holders,Inbox)
    /**Execute the round by sending each stakeholder a sequence of commands */
    /**holders list is shuffled to emulate unpredictable ordering of messages */
    case Update => {
      //if (t%epochLength==1) {send(holders,Status)}
      t+=1
      println("t = "+t.toString)
      send(Random.shuffle(holders),Update(t))
      send(Random.shuffle(holders),Diffuse)
      send(Random.shuffle(holders),ForgeBlocks)
      send(Random.shuffle(holders),UpdateChainFast)
      if (dataOutFlag && t%dataOutInterval==0) send(holders,WriteFile(fileWriter))
    }
    //tells actors to print status */
    case Status => {
      send(holders,Status)
    }
    case value:NewDataFile => if(dataOutFlag) {
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
        case fw: BufferedWriter => fw.write(fileString)
        case _ => println("error: file writer not initialized")
      }
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
    val pi:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = Ed25519VRF.vrfProofToHash(pi)
    val pi_y:Pi = Ed25519VRF.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = Ed25519VRF.vrfProofToHash(pi_y)
    val hash:Hash = eta0
    val r = scala.util.Random
    // set initial stake distribution, set to random value between 0.0 and initStakeMax for each stakeholder
    val state: State = holders.map{ case ref:ActorRef => signTx(
      genesisBytes
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(0))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(1))
        ++hex2bytes(genKeys(s"${ref.path}").split(";")(2)),
      serialize(coordId),sk_sig,pk_sig) -> BigDecimal(initStakeMax * r.nextDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt}.toMap
    var party: Party = List()
    for (holder <- holders){
      val values = genKeys(s"${holder.path}").split(";")
      party ++= List((hex2bytes(values(0)),hex2bytes(values(1)),hex2bytes(values(2))))
    }
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,party,1.0)
    val sig:MalkinSignature = MalkinKES.sign(malkinKey, hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi)
    (hash,state,slot,cert,rho,pi,sig,pk_kes)
  }
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}
