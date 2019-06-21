package crypto.cryptomain

import java.time.Instant
import java.time.temporal.ChronoUnit
import crypto.ouroboros._
import akka.actor.ActorSystem
import scala.util.{Try, Success, Failure}
import scala.io.StdIn
import scala.reflect.io.Path

object cryptoMain extends App {

  /**
    * Ouroboros Prosomoiotís:
    *
    * Dynamic proof of stake protocol simulated with akka actors
    * based on Praos and Genesis revisions of Ouroboros
    *
    */

  val dataFileDir = "/tmp/scorex/test-data/crypto"
  val dataPath = Path(dataFileDir)
  Try(dataPath.deleteRecursively())
  Try(dataPath.createDirectory())

  val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")

  val system = ActorSystem("stakeholders")
  val n = 5

  val coordinator = system.actorOf(Coordinator.props, "coordinator")

  coordinator ! NewDataFile(s"$dataFileDir/ouroboros-data-$dateString.txt")

  coordinator ! Populate(n)

  for (i <- 1 to 100) {
    coordinator ! Update
  }

  coordinator ! CloseDataFile

  println(">>> Press ENTER for Status <<<")
  StdIn.readLine()
  coordinator ! Status

  println(">>> Press ENTER to exit <<<")
  try StdIn.readLine()
  finally system.terminate()

}
