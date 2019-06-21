package crypto.ouroboros

// case objects and classes for pattern matching messages between actors
case object Diffuse
case object Inbox
case object Update
case object UpdateChain
case object UpdateChainFast
case class Update(t:Int)
case class Populate(n:Int)
case class GenBlock(b: Any)
case class SendBlock(b: Any,s:Array[Byte])
case class SendChain(c: Any,s:String)
case class WriteFile(fw: Any)
case class NewDataFile(name:String)
case object CloseDataFile
case object Status
case object ForgeBlocks
case object GetGenKeys
