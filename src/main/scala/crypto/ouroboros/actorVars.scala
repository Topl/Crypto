package crypto.ouroboros

import akka.actor.ActorRef
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper


trait stakeHolderVars
  extends obTypes
    with obMethods
    with utils {
  //list of all or some of the stakeholders, including self, that the stakeholder is aware of
  var holders: List[ActorRef] = List()
  //list of stakeholders that all new blocks and transactions are sent to
  var gossipers: List[ActorRef] = List()
  //map of all session IDs and public keys associated with holders in holder list
  var inbox:Map[Sid,(ActorRef,PublicKeys)] = Map()
  //local stakeholder epoch relative stake
  var alpha = 0.0
  //total number of times this stakeholder was elected slot leader
  var blocksForged = 0
  //slot time as determined from coordinator clock
  var time = 0
  //all tines that are pending built from new blocks that are received
  var tines:Array[(Chain,Int,Int,Int,ActorRef)] = Array()
  //placeholder for genesis block
  var genBlock: Any = 0
  //placeholder for genesis block ID
  var genBlockHash: Hash = ByteArrayWrapper(Array())
  //placeholder for forged block if elected slot leader
  var roundBlock: Any = 0
  //nonce for the epoch
  var eta:Eta = Array()
  //staking threshold for the epoch
  var threshold: Double = 0.0
  //total stake for the current epoch
  var netStake: BigInt = 0
  //total stake from the first epoch
  var netStake0: BigInt = 0
  //max time steps set by coordinator
  var tMax = 0
  //start system time set by coordinator
  var t0:Long = 0
  //current slot that is being processed by stakeholder
  var currentSlot = 0
  //current epoch that is being processed by stakeholder
  var currentEpoch = -1
  //lock for update message
  var updating = false
  //lock for stalling stakeholder
  var actorStalled = false
  //ref of coordinator actor
  var coordinatorRef:ActorRef = _
  //total number of transactions issued
  var txCounter = 0
  //random holder ordering
}

trait coordinatorVars
  extends obTypes
    with obMethods
    with utils {
  //empty list of stake holders
  var holders: List[ActorRef] = List()
  //list of parties
  var parties: List[List[ActorRef]] = List()
  //holder keys for genesis block creation
  var holderKeys:Map[ActorRef,PublicKeyW] = Map()
  //slot
  var t:Slot = 0
  //initial system time
  var t0:Long = 0
  //system time paused offset
  var tp:Long = 0
  //lock for stalling coordinator
  var actorStalled = false
  //lock for pausing system
  var actorPaused = false
  //queue of commands to be processed in a given slot
  var cmdQueue:Map[Slot,String] = inputCommands
  //set of keys so genesis block can be signed and verified by verifyBlock
  val newSeed:String = uuid
  val seed:Array[Byte] = if(randomFlag){
    FastCryptographicHash(uuid)
  }else{
    FastCryptographicHash(inputSeed+"seed")
  }
  //initial nonce for genesis block
  val eta0:Eta = if(randomFlag){
    FastCryptographicHash(uuid)
  }else{
    FastCryptographicHash(inputSeed+"eta0")
  }
  val (sk_sig,pk_sig) = sig.createKeyPair(seed)
  val (sk_vrf,pk_vrf) = vrf.vrfKeypair(seed)
  var sk_kes = kes.generateKey(seed)
  val pk_kes:PublicKey = kes.publicKey(sk_kes)

  val coordData:String = bytes2hex(pk_sig)+":"+bytes2hex(pk_vrf)+":"+bytes2hex(pk_kes)
  val coordKeys:PublicKeys = (pk_sig,pk_vrf,pk_kes)
  //empty list of keys to be populated by stakeholders once they are instantiated
  var genKeys:Map[String,String] = Map()
  var fileWriter:Any = 0
  var graphWriter:Any = 0
  var gossipersMap:Map[ActorRef,List[ActorRef]] = Map()
}
