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

  val forgerReward:BigInt = BigDecimal(1.0e7).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  //percent of transaction amount taken as fee by the forger
  val transferFee = 0.01

  //active slot coefficient, 'difficulty parameter' (0 < f_s < 1)
  val f_s = 0.9

  //epoch length
  val confirmationDepth:Int = 10
  val epochLength:Int = 3*confirmationDepth

  val numGossipers = 6
  val tineMaxTries = 10

  // data write interval in slots
  val dataOutInterval = 10

  // duration of slot in milliseconds
  val slotT:Long = 500

  // time out for dropped messages from coordinator
  val waitTime = 600 seconds

  // duration between update tics that actors send to themselves
  val updateTime = 1.millis

  val commandUpdateTime = (slotT/2).toInt.millis

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
