package crypto.ouroboros

import io.iohk.iodb.ByteArrayWrapper

import scala.collection.immutable.ListMap

class Wallet(pkw:ByteArrayWrapper) extends Types with Parameters with Methods {
  var pendingTxsOut:Map[Sid,Transaction] = Map()
  var availableBalance:BigInt = 0
  var totalBalance:BigInt = 0
  var txCounter:Int = 0
  var confirmedTxCounter:Int = 0
  var netStake:BigInt = 1
  var netStake0:BigInt = 1
  var issueState:State = Map()
  var confirmedState:State = Map()

  def addTx(transaction: Transaction) = {
    if (transaction._1 == pkw) {
      if (!pendingTxsOut.keySet.contains(transaction._4)) {
        pendingTxsOut += (transaction._4 -> transaction)
      }
    }
  }

  def removeTx(transaction: Transaction) = {
    if (transaction._1 == pkw) {
      if (pendingTxsOut.keySet.contains(transaction._4)) {
        pendingTxsOut -= transaction._4
      }
    }
  }

  def getBalance:BigInt = {
    availableBalance = confirmedState(pkw)._1
    availableBalance
  }

  def getTotalBalance:BigInt = {
    totalBalance = issueState(pkw)._1
    totalBalance
  }

  def getTxCounter:Int = {
    txCounter = issueState(pkw)._3
    txCounter
  }

  def getConfirmedTxCounter:Int = {
    confirmedTxCounter = confirmedState(pkw)._3
    confirmedTxCounter
  }

  def update(state:State) = {
    issueState = state
    confirmedState = state
    for (entry <- sortPendingTx) {
      val trans = entry._2
      applyTransaction(issueState,trans,ByteArrayWrapper(Array())) match {
        case value:State => {
          issueState = value
        }
        case _ => {
          println("Wallet error, clearing pending Txs")
          pendingTxsOut = Map()
        }
      }
    }
  }

  def revert(ledger:Ledger) = {
    for (entry <- ledger) {
      entry match {
        case transaction: Transaction => {
          addTx(transaction)
        }
        case _ =>
      }
    }
  }

  def apply(ledger:Ledger) = {
    for (entry <- ledger) {
      entry match {
        case transaction: Transaction => {
          removeTx(transaction)
        }
        case _ =>
      }
    }
  }

  def sortPendingTx = {
    ListMap(pendingTxsOut.toSeq.sortWith(_._2._5 < _._2._5): _*)
  }

  def issueTx(data:(ByteArrayWrapper,BigInt),sk_sig:Array[Byte]): Any = {
    if (issueState.keySet.contains(pkw)) {
      val (pk_r,delta) = data
      val scaledDelta = BigDecimal(delta.toDouble*netStake.toDouble/netStake0.toDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
      val txC = issueState(pkw)._3
      val trans:Transaction = signTransaction(sk_sig,pkw,pk_r,scaledDelta,txC)
      applyTransaction(issueState,trans,ByteArrayWrapper(Array())) match {
        case value:State => {
          issueState = value
          pendingTxsOut += (trans._4->trans)
          trans
        }
        case _ => {
          0
        }
      }
    } else {
      0
    }
  }
}
