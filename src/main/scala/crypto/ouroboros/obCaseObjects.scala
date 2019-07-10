package crypto.ouroboros

import io.iohk.iodb.ByteArrayWrapper

// case objects and classes for pattern matching messages between actors
case object Diffuse
case object Inbox
case object UpdateChain
case object CloseDataFile
case object Status
case object ForgeBlocks
case object GetGenKeys
case object GetTime
case object Update
case object WriteFile
case class CoordRef(ref: Any)
case class GetTime(t1:Long)
case class Run(max:Int)
case class StartTime(t0:Long)
case class Populate(n:Int)
case class GenBlock(b: Any)
case class SendBlock(b: Any,s:String)
case class RequestBlock(h:ByteArrayWrapper, slot:Int, s:String)
case class SendChain(c: Any,s:String)
case class WriteFile(fw: Any)
case class NewDataFile(name:String)
