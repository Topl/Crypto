package crypto.ouroboros

import scala.concurrent.duration._

trait parameters {
  val forgeBytes ="FORGER_REWARD".getBytes
  val transferBytes = "TRANSFER".getBytes
  val genesisBytes = "GENESIS".getBytes
  val forgerReward = BigDecimal(1.0e8).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  val keyLength = 3*32
  val initStakeMax = 1.0e9
  val transferFee = 0.01
  val f_s = 0.9
  val confirmationDepth = 10
  val epochLength = 3*confirmationDepth
  val dataOutInterval = 10
  val slotT:Long = 500
  val waitTime = 60 seconds
  val updateTime = 10.millis
  val performanceFlag = false
  val printFlag = true
  val timingFlag = true
  val dataOutFlag = true
}
