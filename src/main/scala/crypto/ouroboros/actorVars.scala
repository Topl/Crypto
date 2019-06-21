package crypto.ouroboros

import akka.actor.ActorRef
import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.MalkinKey
import scorex.crypto.signatures.Curve25519


trait stakeHolderVars
  extends obTypes
    with obMethods
    with utils {
  var inbox:String = ""
  var stakingParty:Party = List()
  var holderData: String = ""
  var holders: List[ActorRef] = List()
  var diffuseSent = false
  var alpha_Ep = 0.0
  var blocksForged = 0
  var t = 0
  val seed = FastCryptographicHash(uuid)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey:MalkinKey = MalkinKES.generateKey(seed)
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)
  var localChain:Chain = List()
  var foreignChains:List[Chain] = List()
  var genBlock: Any = 0
  var genBlockHash: Array[Byte] = Array()
  var roundBlock: Any = 0
  var eta_Ep:Array[Byte] = Array()
  var Tr_Ep: Double = 0.0
  var holderIndex = -1
  var localState:LocalState = Map()
  var stakingState:LocalState = Map()
  var memPool:MemPool = List()
  val publicKeys = (pk_sig,pk_vrf,pk_kes)

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
  val (sk_sig,pk_sig) = Curve25519.createKeyPair(seed)
  val (sk_vrf,pk_vrf) = Ed25519VRF.vrfKeypair(seed)
  var malkinKey = MalkinKES.generateKey(seed)
  val pk_kes:PublicKey = MalkinKES.publicKey(malkinKey)
  val coordData:String = bytes2hex(pk_sig)+":"+bytes2hex(pk_vrf)+":"+bytes2hex(pk_kes)
  val coordKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  //empty list of keys to be populated by stakeholders once they are instantiated
  var genKeys:Map[String,String] = Map()
  var fileWriter:Any = 0

}
