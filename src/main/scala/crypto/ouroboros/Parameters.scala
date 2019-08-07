package crypto.ouroboros

import scala.concurrent.duration._
import com.typesafe.config.{Config, ConfigFactory}
import java.io.File
import collection.JavaConverters._

trait Parameters {

  def getConfig:Config = {
    import Prosomo.input
    if (input.length > 0) {
      val inputConfigFile = new File(input.head.stripSuffix(".conf")+".conf")
      val localConfig = ConfigFactory.parseFile(inputConfigFile).getConfig("input")
      val baseConfig = ConfigFactory.load
      ConfigFactory.load(localConfig).withFallback(baseConfig)
    } else {
      val baseConfig = ConfigFactory.load
      val localConfig = ConfigFactory.load("local")
      localConfig.withFallback(baseConfig)
    }
  }

  val config:Config = getConfig

  val inputCommands:Map[Int,String] = if (config.hasPath("command")) {
    var out:Map[Int,String] = Map()
    val cmdList = config.getStringList("command.cmd").asScala.toList
    for (line<-cmdList) {
      val com = line.trim.split(" ")
      com(0) match {
        case s:String => {
          if (com.length == 2){
            com(1).toInt match {
              case i:Int => out += (i->s)
              case _ =>
            }
          }
        }
        case _ =>
      }
    }
    out
  } else {
    Map()
  }

  //seed for pseudo random runs
  val inputSeed:String = config.getString("params.inputSeed")
  //number of stakeholders
  val numHolders:Int = config.getInt("params.numHolders")
  //duration of slot in milliseconds
  val slotT:Long = config.getInt("params.slotT")
  // checkpoint depth in slots, k parameter in maxValid-bg
  val k_s:Int = config.getInt("params.k_s")
  //active slot coefficient, 'difficulty parameter' (0 < f_s < 1)
  val f_s:Double = config.getDouble("params.f_s")
  //simulation runtime in slots
  val L_s:Int = config.getInt("params.L_s")
  // epoch length R >= 3k/2f
  val epochLength:Int = 3*(k_s*(0.5/f_s)).toInt
  // slot window for chain selection, s = k/4f
  val slotWindow:Int = (k_s*0.25/f_s).toInt
  //status and verify check chain hash data up to this depth to gauge consensus amongst actors
  val confirmationDepth:Int = config.getInt("params.confirmationDepth")
  //max initial stake
  val initStakeMax:Double = config.getDouble("params.initStakeMax")
  //max random transaction delta
  val maxTransfer:Double = config.getDouble("params.maxTransfer")
  //reward for forging blocks
  val forgerReward:Double = config.getDouble("params.forgerReward")
  //percent of transaction amount taken as fee by the forger
  val transactionFee:Double = config.getDouble("params.transactionFee")
  //number of holders on gossip list for sending new blocks and transactions
  val numGossipers:Int = config.getInt("params.numGossipers")
  //max number of tries for a tine to ask for parent blocks
  val tineMaxTries:Int = config.getInt("params.tineMaxTries")
  //max depth in multiples of confirmation depth that can be returned from an actor
  val tineMaxDepth:Int = config.getInt("params.tineMaxDepth")
  //data write interval in slots
  val dataOutInterval:Int = epochLength
  //time out for dropped messages from coordinator
  val waitTime:FiniteDuration = config.getInt("params.waitTime") seconds
  //duration between update tics that stakeholder actors send to themselves
  val updateTime:FiniteDuration = config.getInt("params.updateTime") millis
  //duration between command read tics and transaction generation for the coordinator
  val commandUpdateTime:FiniteDuration = (slotT/2).toInt millis
  //Issue random transactions if true
  var transactionFlag:Boolean = config.getBoolean("params.transactionFlag")
  // p = 1/txDenominator => 2*(1-p)^numHolders chance of issuing transaction per slot, lower means more txs
  var txDenominator:Int = config.getInt("params.txDenominator")
  //uses randomness for public key seed and initial stake, set to false for deterministic run
  val randomFlag:Boolean = config.getBoolean("params.randomFlag")
  //when true, if system cpu load is too high the coordinator will stall to allow stakeholders to catch up
  val performanceFlag:Boolean = config.getBoolean("params.performanceFlag")
  //threshold of cpu usage above which coordinator will stall if performanceFlag = true
  val systemLoadThreshold:Double = config.getDouble("params.systemLoadThreshold")
  //number of values to average for load threshold
  val numAverageLoad:Int = config.getInt("params.numAverageLoad")
  //print Stakeholder 0 status per slot if true
  val printFlag:Boolean = config.getBoolean("params.printFlag")
  //print Stakeholder 0 execution time per slot if true
  val timingFlag:Boolean = config.getBoolean("params.timingFlag")
  //Record data if true, plot data points with ./cmd.sh and enter command: plot
  val dataOutFlag:Boolean = config.getBoolean("params.dataOutFlag")
  //path for data output files
  val dataFileDir:String = config.getString("params.dataFileDir")
}
