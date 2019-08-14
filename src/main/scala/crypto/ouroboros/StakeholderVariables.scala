package crypto.ouroboros

import akka.actor.ActorRef
import io.iohk.iodb.ByteArrayWrapper

trait StakeholderVariables
  extends Types
    with Methods
    with Utils {
  //list of all or some of the stakeholders, including self, that the stakeholder is aware of
  var holders: List[ActorRef] = List()
  //list of stakeholders that all new blocks and transactions are sent to
  var gossipers: List[ActorRef] = List()
  //gossipers offset
  var gOff = 0
  //number of tries to issue hello in slots
  var numHello = 0
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
  //set of all txs issued by holder
  var setOfTxs:Map[Sid,Int] = Map()
}

