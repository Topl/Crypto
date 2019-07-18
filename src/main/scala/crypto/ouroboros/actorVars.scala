package crypto.ouroboros

import akka.actor.ActorRef
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper


trait stakeHolderVars
  extends obTypes
    with obMethods
    with utils {
  var inbox:String = ""
  var holders: List[ActorRef] = List()
  var alpha_Ep = 0.0
  var blocksForged = 0
  var time = 0
  var foreignChains:List[BlockId] = List()
  var genBlock: Any = 0
  var genBlockHash: Hash = ByteArrayWrapper(Array())
  var roundBlock: Any = 0
  var eta_Ep:Eta = Array()
  var Tr_Ep: Double = 0.0
  var tMax = 0
  var t0:Long = 0
  var currentSlot = 0
  var currentEpoch = -1
  var updating = false
  var actorStalled = false
  var coordinatorRef:ActorRef = _

}

trait coordinatorVars
  extends obTypes
    with obMethods
    with utils {
  //empty list of stake holders
  var holders: List[ActorRef] = List()
  //initial nonce for genesis block
  val eta0:Eta = if(randomFlag){
    FastCryptographicHash(uuid)
  }else{
    FastCryptographicHash(Array(0x00.toByte))
  }
  //slot
  var t = 0
  //set of keys so gensis block can be signed and verified by verifyBlock
  val seed:Array[Byte] = if(randomFlag){
    FastCryptographicHash(uuid)
  }else{
    FastCryptographicHash(Array(0xFF.toByte))
  }
  val (sk_sig,pk_sig) = sig.createKeyPair(seed)
  val (sk_vrf,pk_vrf) = vrf.vrfKeypair(seed)
  var malkinKey = kes.generateKey(seed)
  val pk_kes:PublicKey = kes.publicKey(malkinKey)
  val coordData:String = bytes2hex(pk_sig)+":"+bytes2hex(pk_vrf)+":"+bytes2hex(pk_kes)
  val coordKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  //empty list of keys to be populated by stakeholders once they are instantiated
  var genKeys:Map[String,String] = Map()
  var fileWriter:Any = 0
}
