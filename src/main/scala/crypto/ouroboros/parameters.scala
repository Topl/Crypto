package crypto.ouroboros

import scala.concurrent.duration._

trait parameters {
  val forgeBytes ="FORGER_REWARD".getBytes
  val transferBytes = "TRANSFER".getBytes
  val genesisBytes = "GENESIS".getBytes
  val forgerReward = BigDecimal(1.0e8).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  val keyLength = 3*32

  //max initial stake
  val initStakeMax = 1.0e9
  //percent of transaction amount taken as fee by the forger
  val transferFee = 0.01

  //active slot coefficient, 'difficulty parameter' (0 < f_s < 1)
  val f_s = 0.9

  //epoch length
  val confirmationDepth:Int = 10
  val epochLength:Int = 3*confirmationDepth

  // data write interval in slots
  val dataOutInterval = 100

  // duration of slot in milliseconds
  val slotT:Long = 100

  // time out for dropped messages from coordinator
  val waitTime = 600 seconds

  // duration between update tics that actors send to themselves
  val updateTime = 1.millis

  val commandUpdateTime = 200.millis

  // skips some verification for faster performance if true
  val performanceFlag = false

  // print holder 0 status per slot if true
  val printFlag = true

  // print holder 0 execution time per slot if true
  val timingFlag = true

  // record data if true
  val dataOutFlag = false
}
