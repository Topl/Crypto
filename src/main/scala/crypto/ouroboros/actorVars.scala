package crypto.ouroboros

import akka.actor.ActorRef
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper


trait stakeHolderVars
  extends obTypes
    with obMethods
    with utils {
  var inbox:String = ""
  var holderData: String = ""
  var holders: List[ActorRef] = List()
  var diffuseSent = false
  var alpha_Ep = 0.0
  var blocksForged = 0
  var time = 0
  val seed = FastCryptographicHash(uuid)
  val (sk_vrf,pk_vrf) = vrf.vrfKeypair(seed)
  var malkinKey:MalkinKey = kes.generateKey(seed)
  val (sk_sig,pk_sig) = sig.createKeyPair(seed)
  val pk_kes:PublicKey = kes.publicKey(malkinKey)
  var localChain:Chain = Array()
  var foreignChains:List[Chain] = List()
  var genBlock: Any = 0
  var genBlockHash: Hash = ByteArrayWrapper(Array())
  var roundBlock: Any = 0
  var eta_Ep:Eta = Array()
  var eta_prev:Eta = Array()
  var Tr_Ep: Double = 0.0
  var holderIndex = -1
  var localState:LocalState = Map()
  var stakingState:LocalState = Map()
  var history:List[(Eta,LocalState)] = List()
  var memPool:MemPool = List()
  val publicKeys = (pk_sig,pk_vrf,pk_kes)
  var tMax = 0
  var t0:Long = 0
  var currentSlot = 0
  var currentEpoch = -1
  var updating = false
  var coordinatorRef:ActorRef = _
  //stakeholder public keys
  holderData = bytes2hex(pk_sig)+";"+bytes2hex(pk_vrf)+";"+bytes2hex(pk_kes)

}

trait coordinatorVars
  extends obTypes
    with obMethods
    with utils {
  //empty list of stake holders
  var holders: List[ActorRef] = List()
  //initial nonce for genesis block
  val eta0 = FastCryptographicHash(uuid)
  //slot
  var t = 0
  //set of keys so gensis block can be signed and verified by verifyBlock
  val seed = FastCryptographicHash(uuid)
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
