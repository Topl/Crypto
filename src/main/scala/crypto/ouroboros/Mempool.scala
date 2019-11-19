package crypto.ouroboros

import scala.collection.immutable.ListMap

class Mempool extends Types {

  val txMaxTries = 100

  var transactions:Map[Sid,(Transaction,Int)] = Map()

  def known(transaction: Transaction):Boolean = {
    transactions.keySet.contains(transaction._4)
  }

  def add(transaction: Transaction):Unit = {
    if (!transactions.keySet.contains(transaction._4)) transactions += (transaction._4->(transaction,0))
  }

  def add(ledger:Ledger):Unit = {
    for (entry<-ledger) {
      entry match {
        case transaction:Transaction => {
          add(transaction)
        }
        case _ =>
      }
    }
  }

  def update(ls:State):Unit = {
    for (entry <- transactions) {
      if (entry._2._2 < txMaxTries) {
        val cnt = entry._2._2 + 1
        transactions -= entry._1
        transactions += (entry._1 -> (entry._2._1,cnt))
      } else {
        transactions -= entry._1
      }
      if (entry._2._1._5 < ls(entry._2._1._1)._3) {
        transactions -= entry._1
      }
    }
  }

  def getBuffer:ListMap[Sid,(Transaction,Int)] = {
    ListMap(transactions.toSeq.sortWith(_._2._1._5 < _._2._1._5): _*)
  }

}
