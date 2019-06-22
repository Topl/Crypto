package crypto.ouroboros

import scala.concurrent.duration._

trait parameters {
  val f_s = 0.9
  val forgerReward = BigDecimal(1.0e8).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  val transferFee = 0.01
  val confirmationDepth = 10
  val epochLength = 3*confirmationDepth
  val initStakeMax = 1.0e9
  val waitTime = 60 seconds
  val timingFlag = true
  val performanceFlag = false
  val printFlag = true
  val dataOutFlag = true
  val dataOutInterval = 10
  val forgeBytes ="FORGER_REWARD".getBytes
  val transferBytes = "TRANSFER".getBytes
  val genesisBytes = "GENESIS".getBytes
  val keyLength = 3*32
  val slotT:Long = 1000
  val updateTime = 10.millis
}
