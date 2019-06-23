package crypto.ouroboros

import java.time.Instant
import java.time.temporal.ChronoUnit

import akka.actor.ActorSystem

import scala.io.StdIn
import scala.reflect.io.Path
import scala.util.Try

object Prosomo extends App {

  /**
    * Ouroboros Prosomoiotís:
    *
    * Dynamic proof of stake protocol simulated with akka actors
    * based on Praos and Genesis revisions of Ouroboros
    *
    */

  val dataFileDir = "/tmp/scorex/test-data/crypto"
  val dataPath = Path(dataFileDir)
  //Try(dataPath.deleteRecursively())
  //Try(dataPath.createDirectory())

  val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")

  val system = ActorSystem("stakeholders")

  val coordinator = system.actorOf(Coordinator.props, "coordinator")

  coordinator ! NewDataFile(s"$dataFileDir/ouroboros-data-$dateString.txt")

  coordinator ! Populate(5)

  coordinator ! Run(200)

  println(">>> Press ENTER for Status <<<")
  StdIn.readLine()
  coordinator ! CloseDataFile
  coordinator ! Status
  println(">>> Press ENTER to exit <<<")
  try StdIn.readLine()
  finally system.terminate()

}
