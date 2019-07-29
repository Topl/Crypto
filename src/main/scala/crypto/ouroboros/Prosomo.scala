package crypto.ouroboros

import java.time.Instant
import java.time.temporal.ChronoUnit

import akka.actor.ActorSystem

import scala.io.StdIn
import scala.reflect.io.Path
import scala.util.Try

object Prosomo extends App with parameters {

  /**
    * Ouroboros Prosomoiotís:
    *
    * Dynamic proof of stake protocol simulated with akka actors
    * based on Praos and Genesis revisions of Ouroboros
    *
    */


  val dataPath = Path(dataFileDir)
  //Try(dataPath.deleteRecursively())
  Try(dataPath.createDirectory())

  val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")

  val system = ActorSystem("Stakeholders")

  val coordinator = system.actorOf(Coordinator.props, "Coordinator")

  coordinator ! NewDataFile(s"$dataFileDir/ouroboros-data-$dateString.data")

  coordinator ! Populate(numHolders)

  coordinator ! Run(L_s)

  println("-->Press ENTER to exit<--")
  try StdIn.readLine()
  finally {
    coordinator ! CloseDataFile
    system.terminate()
  }

}
