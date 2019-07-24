package crypto.ouroboros

import io.iohk.iodb.ByteArrayWrapper

import scala.concurrent.duration._

trait parameters {
  val forgeBytes = ByteArrayWrapper("FORGER_REWARD".getBytes)
  val transferBytes = ByteArrayWrapper("TRANSFER".getBytes)
  val genesisBytes = ByteArrayWrapper("GENESIS".getBytes)
  val keyLength = 3*32
  //max initial stake
  val initStakeMax = 1.0e9
  //max random transaction delta
  val maxTransfer = 1.0e7
  val forgerReward:BigInt = BigDecimal(1.0e5).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  //percent of transaction amount taken as fee by the forger
  val transferFee = 0.01

  /**
    * Main Ouroboros Epoch parameters
    */
  //active slot coefficient, 'difficulty parameter' (0 < f_s < 1)
  val f_s = 0.9
  // checkpoint depth in slots, k parameter in maxValid-bg
  val k_s:Int = 100
  // epoch length R >= 3k/2f
  val epochLength:Int = 3*(k_s*(0.5/f_s)).toInt
  // slot window for chain selection, s = k/4f
  val slotWindow:Int = (k_s*0.25/f_s).toInt

  //status and verify check chain hash data up to this depth to gauge consensus amongst actors
  val confirmationDepth = 10

  val numGossipers = 6
  val tineMaxTries = 10
  val tineMaxDepth = 10

  // data write interval in slots
  val dataOutInterval = epochLength

  // duration of slot in milliseconds
  val slotT:Long = 500

  // time out for dropped messages from coordinator
  val waitTime = 600 seconds

  // duration between update tics that actors send to themselves
  val updateTime = 1.millis

  val commandUpdateTime = (slotT/2).toInt.millis

  // issue random transactions if true
  var transactionFlag = true

  //uses randomness for public key seed and initial stake, set to false for deterministic run
  //still depends on number of actors
  val randomFlag = true

  // skips some verification for faster performance if true
  val performanceFlag = false

  // print holder 0 status per slot if true
  val printFlag = true

  // print holder 0 execution time per slot if true
  val timingFlag = false

  // record data if true
  val dataOutFlag = true
}
