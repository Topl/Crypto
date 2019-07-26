package crypto.ouroboros

import scala.concurrent.duration._

trait parameters {

  //max initial stake
  val initStakeMax = 1.0e9

  //max random transaction delta
  val maxTransfer = 1.0e9

  //reward for forging blocks
  val forgerReward = 1.0e7

  //percent of transaction amount taken as fee by the forger
  val transferFee = 0.01

  //active slot coefficient, 'difficulty parameter' (0 < f_s < 1)
  val f_s = 0.9

  // checkpoint depth in slots, k parameter in maxValid-bg
  val k_s:Int = 30

  // epoch length R >= 3k/2f
  val epochLength:Int = 3*(k_s*(0.5/f_s)).toInt

  // slot window for chain selection, s = k/4f
  val slotWindow:Int = (k_s*0.25/f_s).toInt

  //status and verify check chain hash data up to this depth to gauge consensus amongst actors
  val confirmationDepth = 10

  //number of holders on gossip list for sending new blocks and transactions
  val numGossipers = 6

  //max number of tries for a tine to ask for parent blocks
  val tineMaxTries = 10

  //max depth in multiples of confirmation depth that can be returned from an actor
  val tineMaxDepth = 10

  //data write interval in slots
  val dataOutInterval = epochLength

  //duration of slot in milliseconds
  val slotT:Long = 200

  //time out for dropped messages from coordinator
  val waitTime = 600 seconds

  //duration between update tics that stakeholder actors send to themselves
  val updateTime = 1.millis

  //duration between command read tics and transaction generation for the coordinator
  val commandUpdateTime = (slotT/2).toInt.millis

  //Issue random transactions if true
  var transactionFlag = true

  //uses randomness for public key seed and initial stake, set to false for deterministic run
  val randomFlag = true

  //when true, if system cpu load is too high the coordinator will stall to allow stakeholders to catch up
  val performanceFlag = true

  //threshold of cpu usage above which coordinator will stall if performanceFlag = true
  val systemLoadThreshold = 0.95

  //number of values to average for load threshold
  val numAverageLoad = 3

  //print Stakeholder 0 status per slot if true
  val printFlag = true

  //print Stakeholder 0 execution time per slot if true
  val timingFlag = false

  //Record data if true, plot data points with ./cmd.sh and enter command: plot
  val dataOutFlag = true
}
