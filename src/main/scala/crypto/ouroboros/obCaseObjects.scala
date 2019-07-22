package crypto.ouroboros

import io.iohk.iodb.ByteArrayWrapper

// case objects and classes for pattern matching messages between actors
case object Diffuse
case object Inbox
case object CloseDataFile
case object Status
case object GetGenKeys
case object GetTime
case object Update
case object WriteFile
case object StallActor
case object ReadCommand
case object Verify
case class CoordRef(ref: Any)
case class GetTime(t1:Long)
case class Run(max:Int)
case class StartTime(t0:Long)
case class Populate(n:Int)
case class GenBlock(b: Any)
case class SendBlock(s:Any)
case class RequestBlock(s:Any)
case class RequestChain(s:Any)
case class ReturnBlock(s:Any)
case class SendTx(s:Any)
case class IssueTx(s:Any)
case class WriteFile(fw: Any)
case class NewDataFile(name:String)
case class Party(list:Any,clear:Boolean)
