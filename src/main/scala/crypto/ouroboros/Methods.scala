package crypto.ouroboros

import akka.actor.ActorRef
import akka.actor._
import akka.pattern.ask
import akka.util.Timeout

import scala.concurrent.Await
import scala.language.postfixOps
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import scala.collection.immutable.ListMap
import util.control.Breaks._
import scala.math.BigInt
import scala.util.Random

trait Methods
  extends Types
    with Parameters
    with Utils {

  //tags for identifying ledger entries
  val forgeBytes = ByteArrayWrapper("FORGER_REWARD".getBytes)
  val genesisBytes = ByteArrayWrapper("GENESIS".getBytes)

  //vars for chain, blocks, state, history, and locks
  var localChain:Chain = Array()
  var blocks:ChainData = Array()
  var chainHistory:ChainHistory = Array()
  var localState:State = Map()
  var issueState:State = Map()
  var stakingState:State = Map()
  var history_state:Array[State] = Array()
  var history_eta:Array[Eta] = Array()
  var memPool:MemPool = Map()
  var holderIndex:Int = -1
  var diffuseSent = false

  //verification and signing objects
  val vrf = new Vrf
  val kes = new Kes
  val sig = new Sig

  var rng:Random = new Random
  var routerRef:ActorRef = _

  /**
    * retrieve a block from database
    * @param bid
    * @return block if found, 0 otherwise
    */
  def getBlock(bid:BlockId): Any = {
    if (bid._1 >= 0 && !bid._2.data.isEmpty) {
      if (blocks(bid._1).contains(bid._2)) {
        blocks(bid._1)(bid._2)
      } else {
        0
      }
    } else {
      0
    }
  }

  /**
    * retrieve parent block
    * @param b
    * @return parent block if found, 0 otherwise
    */
  def getParentBlock(b:Block): Any = {
    if (b._10 >= 0 && !b._1.data.isEmpty) {
      if (blocks(b._10).contains(b._1)) {
        blocks(b._10)(b._1)
      } else {
        0
      }
    } else {
      0
    }
  }

  /**
    * retrieve parent block id
    * @param bid
    * @return parent id if found, 0 otherwise
    */
  def getParentId(bid:BlockId): Any = {
    getBlock(bid) match {
      case b:Block => (b._10,b._1)
      case _ => 0
    }
  }

  /**
    * retrieve parent block id from block
    * @param b
    * @return parent id
    */
  def getParentId(b:Block): BlockId = {
    (b._10,b._1)
  }

  /**
    * finds the last non-empty slot in a chain
    * @param c chain of block ids
    * @param s slot to start search
    * @return last active slot found on chain c starting at slot s
    */
  def lastActiveSlot(c:Chain,s:Slot): Slot = {
    var i = s
    while (c(i)._2.data.isEmpty) {
      i-=1
    }
    i
  }

  /**
    * returns the total number of active slots on a chain
    * @param c chain of block ids
    * @return total active slots
    */
  def getActiveSlots(c:Chain): Int = {
    var i = 0
    for (id<-c) {
      if (!id._2.data.isEmpty) {
        i+=1
      }
    }
    i
  }

  /**
    * main hash routine used in prosomo
    * @param input any bytes
    * @return wrapped byte array
    */
  def hash(input:Any): ByteArrayWrapper = {
    ByteArrayWrapper(FastCryptographicHash(serialize(input)))
  }

  /**
    * calculates epoch nonce recursively
    * @param c local chain to be verified
    * @param ep epoch derived from time step
    * @return hash nonce
    */
  def eta(c:Chain,ep:Int): Eta = {
    if(ep == 0) {
      getBlock(c(0)) match {
        case b:Block => b._1.data
        case _ => Array()
      }
    } else {
      var v: Array[Byte] = Array()
      val epcv = subChain(c,ep*epochLength-epochLength,ep*epochLength-epochLength/3)
      val cnext = subChain(c,0,ep*epochLength-epochLength)
      for(id <- epcv) {
        getBlock(id) match {
          case b:Block => v = v++b._5
          case _ =>
        }
      }
      FastCryptographicHash(eta(cnext,ep-1)++serialize(ep)++v)
    }
  }

  /**
    * calculates epoch nonce from previous nonce
    * @param c local chain to be verified
    * @param ep epoch derived from time step
    * @param etaP previous eta
    * @return hash nonce
    */
  def eta(c:Chain,ep:Int,etaP:Eta): Eta = {
    if(ep == 0) {
      getBlock(c(0)) match {
        case b:Block => b._1.data
        case _ => Array()
      }
    } else {
      var v: Array[Byte] = Array()
      val epcv = subChain(c,ep*epochLength-epochLength,ep*epochLength-epochLength/3)
      for(id <- epcv) {
        getBlock(id) match {
          case b:Block => v = v++b._5
          case _ =>
        }
      }
      val eta_ep = FastCryptographicHash(etaP++serialize(ep)++v)
      eta_ep
    }
  }

  /**
    * returns a sub-chain containing all blocks in a given time interval
    * @param c input chain
    * @param t1 slot lower bound
    * @param t2 slot upper bound
    * @return all blocks in the interval t1 to t2, including blocks of t1 and t2
    */
  def subChain(c:Chain,t1:Int,t2:Int): Chain = {
    var t_lower:Int = 0
    var t_upper:Int = 0
    if (t1>0) t_lower = t1
    if (t2>0) t_upper = t2
    c.slice(t_lower,t_upper+1)
  }

  /**
    * expands a tine to have empty slots in between active slots
    * @param c dense chain
    * @param p prefix slot
    * @return expanded tine
    */
  def expand(c:Chain,p:Slot): Chain ={
    val out = Array.fill(c.last._1-p){(-1,ByteArrayWrapper(Array()))}
    for (id <- c) {
      out.update(id._1-p-1,id)
    }
    out
  }

  /**
    * Aggregate staking function used for calculating threshold per epoch
    * @param a relative stake
    * @param f active slot coefficient
    * @return probability of being elected slot leader
    */
  def phi (a:Double,f:Double): Double = {
    1.0 - scala.math.pow(1.0 - f,a)
  }

  /**
    * Compares the vrf output to the threshold
    * @param y vrf output bytes
    * @param t threshold between 0.0 and 1.0
    * @return true if y mapped to double between 0.0 and 1.0 is less than threshold
    */
  def compare(y: Array[Byte],t: Double):Boolean = {
    var net = 0.0
    var i =0
    for (byte<-y){
      i+=1
      val n = BigInt(byte & 0xff).toDouble
      val norm = scala.math.pow(2.0,8.0*i)
      net += n/norm
    }
    net<t
  }

  /**
    * Verifiable string for communicating between stakeholders
    * @param str data to be diffused
    * @param id holder identification information
    * @param sk_sig holder signature secret key
    * @return string to be diffused
    */
  def diffuse(str: String,id: String,sk_sig: PrivateKey): String = {
    str+";"+id+";"+bytes2hex(sig.sign(sk_sig,serialize(str+";"+id)))
  }

  /**
    * Signed data box for verification between holders
    * @param data any data
    * @param id session id
    * @param sk_sig sig private key
    * @param pk_sig sig public key
    * @return signed box
    */
  def signBox(data: Any, id:Sid, sk_sig: PrivateKey, pk_sig: PublicKey): Box = {
    (data,id,sig.sign(sk_sig,serialize(data)++id.data),pk_sig)
  }

  /**
    * verify a
    * @param box
    * @return
    */
  def verifyBox(box:Box): Boolean = {
    sig.verify(box._3,serialize(box._1)++box._2.data,box._4)
  }

  /**
    * picks set of gossipers randomly
    * @param id self ref not to include
    * @param h list of holders
    * @return list of gossipers
    */
  def gossipSet(id:ActorPath,h:List[ActorRef]):List[ActorRef] = {
    var out:List[ActorRef] = List()
    for (holder <- rng.shuffle(h)) {
      if (holder.path != id && out.length < numGossipers) {
        out = holder::out
      }
    }
    out
  }

  /**
    * Sends command to one of the stakeholders
    * @param holder actor list
    * @param command object to be sent
    */
  def send(sender:ActorRef,holder:ActorRef,command: Any) = {
    if (useRouting) {
      routerRef ! (sender,holder,command)
    } else {
      holder ! command
    }
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    */
  def send(sender:ActorRef,holders:List[ActorRef],command: Any) = {
    for (holder <- holders){
      if (useRouting) {
        routerRef ! (sender,holder,command)
      } else {
        holder ! command
      }
    }
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    */
  def sendAssertDone(holders:List[ActorRef], command: Any) = {
    for (holder <- holders){
      implicit val timeout:Timeout = Timeout(waitTime)
      val future = holder ? command
      val result = Await.result(future, timeout.duration)
      assert(result == "done")
    }
  }

  /**
    * Sends command to stakeholder and waits for response
    * @param holder
    * @param command
    */
  def sendAssertDone(holder:ActorRef, command: Any) = {
    implicit val timeout:Timeout = Timeout(waitTime)
    val future = holder ? command
    val result = Await.result(future, timeout.duration)
    assert(result == "done")
  }

  /**
    * returns map of gossipers to coordinator
    * @param holders
    * @return map of actor ref to its list of gossipers
    */
  def getGossipers(holders:List[ActorRef]):Map[ActorRef,List[ActorRef]] = {
    var gossipersMap:Map[ActorRef,List[ActorRef]] = Map()
    for (holder <- holders){
      implicit val timeout:Timeout = Timeout(waitTime)
      val future = holder ? RequestGossipers
      val result = Await.result(future, timeout.duration)
      result match {
        case value:GetGossipers => {
          value.list match {
            case l:List[ActorRef] => gossipersMap += (holder->l)
            case _ => println("error")
          }
        }
        case _ => println("error")
      }
    }
    gossipersMap
  }

  /**
    * returns the staking state to the coordinator
    * @param holder
    * @return
    */
  def getStakingState(holder:ActorRef):State = {
    var state:State = Map()
      implicit val timeout:Timeout = Timeout(waitTime)
      val future = holder ? RequestState
      val result = Await.result(future, timeout.duration)
      result match {
        case value:GetState => {
          value.s match {
            case s:State => state = s
            case _ => println("error")
          }
        }
        case _ => println("error")
      }
    state
  }

  /**
    * sets the local chain history and block data to the holders
    * @param holder actor to get data from
    */
  def getBlockTree(holder:ActorRef) = {
    implicit val timeout:Timeout = Timeout(waitTime)
    val future = holder ? RequestBlockTree
    val result = Await.result(future, timeout.duration)
    result match {
      case value:GetBlockTree => {
        value.t match {
          case t:ChainData => blocks = t
          case _ => println("error")
        }
        value.h match {
          case h:ChainHistory => chainHistory = h
          case _ => println("error")
        }
      }
      case _ => println("error")
    }
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    * @param input map of holder data
    * @return map of holder data
    */
  def collectKeys(holders:List[ActorRef], command: Any, input: Map[String,String]): Map[String,String] = {
    var list:Map[String,String] = input
    for (holder <- holders){
      implicit val timeout:Timeout = Timeout(waitTime)
      val future = holder ? command
      Await.result(future, timeout.duration) match {
        case str:String => {
          if (verifyStamp(str)) list = list++Map(s"${holder.path}" -> str)
        }
        case _ => println("error")
      }
    }
    list
  }

  /**
    * send diffuse message between holders, used for populating inbox
    * @param holderId
    * @param holders
    * @param command
    */
  def sendDiffuse(holderId:ActorPath, holders:List[ActorRef], command: Box) = {
    for (holder <- holders){
      implicit val timeout:Timeout = Timeout(waitTime)
      if (holder.path != holderId) {
        val future = holder ? command
        val result = Await.result(future, timeout.duration)
        assert(result == "done")
      }
    }
    diffuseSent = true
  }

  /**
    * Block verify using key evolving signature
    * @param b input block
    * @returnt true if signature is valid, false otherwise
    */
  def verifyBlock(b:Block): Boolean = {
    val (hash, state, slot, cert, rho, pi, sig, pk_kes, bn,ps) = b
    kes.verify(pk_kes,hash.data++serialize(state)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps),sig,slot)
  }

  /**
    * Verify chain using key evolving signature, VRF proofs, and hash id
    * @param c chain to be verified
    * @param gh genesis block hash
    * @return true if chain is valid, false otherwise
    */
  def verifyChain(c:Chain, gh:Hash): Boolean = {
    var bool = true
    var ep = -1
    var alpha_Ep = 0.0
    var tr_Ep = 0.0
    var eta_Ep: Eta = eta(c, 0)
    var stakingState: State = Map()
    var pid:BlockId = (0,gh)
    var i = 0

    getBlock(c(0)) match {
      case b:Block => bool &&= hash(b) == gh
      case _ => bool &&= false
    }

    for (id <- c.tail) {
      getBlock(id) match {
        case b:Block => {
          getParentBlock(b) match {
            case pb:Block => {
              bool &&= getParentId(b) == pid
              if (getParentId(b) != pid) println("Holder "+holderIndex.toString+" pid mismatch")
              compareBlocks(pb,b)
              pid = id
            }
            case _ => bool &&= false
          }
        }
        case _ =>
      }
    }

    def compareBlocks(parent: Block, block: Block) = {
      val (h0, _, slot, cert, rho, pi, _, pk_kes, bn, ps) = block
      val (pk_vrf, y, pi_y, pk_sig, tr_c) = cert
      while(i<=slot) {
        if (i/epochLength > ep) {
          ep = i/epochLength
          eta_Ep = eta(c, ep, eta_Ep)
          stakingState = updateLocalState(stakingState,subChain(c,(i/epochLength)*epochLength-2*epochLength+1,(i/epochLength)*epochLength-epochLength))
        }
        i+=1
      }
      alpha_Ep = relativeStake((pk_sig, pk_vrf, pk_kes), stakingState)
      tr_Ep = phi(alpha_Ep, f_s)
      bool &&= (
        hash(parent) == h0
          && verifyBlock(block)
          && parent._3 == ps
          && parent._9 + 1 == bn
          && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi)
          && vrf.vrfProofToHash(pi).deep == rho.deep
          && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y)
          && vrf.vrfProofToHash(pi_y).deep == y.deep
          && tr_Ep == tr_c
          && compare(y, tr_Ep)
        )
      if (!bool) {
        print(slot)
        print(" ")
        println(Seq(
          hash(parent) == h0 //1
          , verifyBlock(block) //2
          , parent._3 == ps //3
          , parent._9 + 1 == bn //4
          , vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi) //5
          , vrf.vrfProofToHash(pi).deep == rho.deep //6
          , vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y) //7
          , vrf.vrfProofToHash(pi_y).deep == y.deep //8
          , tr_Ep == tr_c //9
          , compare(y, tr_Ep) //10
        ))
      }
    }
    bool
  }

  /**
    * Verify chain using key evolving signature, VRF proofs, and hash rule
    * @param tine chain to be verified
    * @return true if chain is valid, false otherwise
    */
  def verifySubChain(tine:Chain,prefix:Slot): Boolean = {
    val ep0 = prefix/epochLength
    var eta_Ep:Eta = history_eta(ep0)
    var stakingState: State = {
      if (ep0 > 1) {history_state((ep0-1)*epochLength)} else {history_state(0)}
    }
    var ep = ep0
    var bool = true
    var alpha_Ep = 0.0
    var tr_Ep = 0.0
    var pid:BlockId = (0,ByteArrayWrapper(Array()))
    var i = prefix+1

    breakable{
      for (id<-tine) {
        if (!id._2.data.isEmpty) {
          pid = getParentId(id) match {case value:BlockId => value}
          break()
        }
      }
      bool &&= false
    }

    for (id <- tine) {
      getBlock(id) match {
        case b:Block => {
          getParentBlock(b) match {
            case pb:Block => {
              bool &&= getParentId(b) == pid
              compareBlocks(pb,b)
              pid = id
            }
            case _ => bool &&= false
          }
        }
        case _ =>
      }
    }

    def compareBlocks(parent:Block,block:Block) = {
      val (h0, _, slot, cert, rho, pi, _, pk_kes,bn,ps) = block
      val (pk_vrf, y, pi_y, pk_sig, tr_c) = cert
      while(i<=slot) {
        if (i/epochLength > ep) {
          ep = i/epochLength
          if (ep0 + 1 == ep) {
            eta_Ep = eta(subChain(localChain, 0, prefix) ++ tine, ep, eta_Ep)
            stakingState = history_state((ep - 1) * epochLength)
          } else {
            eta_Ep = eta(subChain(localChain, 0, prefix) ++ tine, ep, eta_Ep)
            stakingState = updateLocalState(stakingState, subChain(subChain(localChain, 0, prefix) ++ tine, (i / epochLength) * epochLength - 2 * epochLength + 1, (i / epochLength) * epochLength - epochLength))
          }
        }
        i+=1
      }
      alpha_Ep = relativeStake((pk_sig,pk_vrf,pk_kes),stakingState)
      tr_Ep = phi(alpha_Ep, f_s)
      bool &&= (
             hash(parent) == h0
          && verifyBlock(block)
          && parent._3 == ps
          && parent._9+1 == bn
          && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi)
          && vrf.vrfProofToHash(pi).deep == rho.deep
          && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y)
          && vrf.vrfProofToHash(pi_y).deep == y.deep
          && tr_Ep == tr_c
          && compare(y, tr_Ep)
        )
      if(!bool){
        print("Error: Holder "+holderIndex.toString+" ");print(slot);print(" ")
        println(Seq(
            hash(parent) == h0 //1
          , verifyBlock(block) //2
          , parent._3 == ps //3
          , parent._9+1 == bn //4
          , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("NONCE"),pi) //5
          , vrf.vrfProofToHash(pi).deep == rho.deep //6
          , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("TEST"),pi_y) //7
          , vrf.vrfProofToHash(pi_y).deep == y.deep //8
          , tr_Ep == tr_c //9
          , compare(y,tr_Ep) //10
        ))
        println("Holder "+holderIndex.toString+" Epoch:"+(slot/epochLength).toString+"\n"+"Eta:"+bytes2hex(eta_Ep))
      }
    }

    if(!bool) sharedData.throwError
    if (sharedData.error) {
      for (id<-subChain(localChain,0,prefix)++tine) {
        if (id._1 > -1) println("H:"+holderIndex.toString+"S:"+id._1.toString+"ID:"+bytes2hex(id._2.data))
      }
    }
    bool
  }

  /**
    * calculates alpha, the epoch relative stake, from the staking state
    * @param holderKeys
    * @param ls
    * @return
    */
  def relativeStake(holderKeys:PublicKeys,ls:State): Double = {
    var netStake:BigInt = 0
    var holderStake:BigInt = 0
    for (member <- ls.keySet) {
      val (balance,activityIndex,txC) = ls(member)
      if (activityIndex) netStake += balance
    }
    val holderKey = ByteArrayWrapper(holderKeys._1++holderKeys._2++holderKeys._3)
    if (ls.keySet.contains(holderKey)){
      val (balance,activityIndex,txC) = ls(holderKey)
      if (activityIndex) holderStake += balance
    }
    if (netStake > 0) {
      holderStake.toDouble / netStake.toDouble
    } else {
      0.0
    }
  }

  /**
    * verify a signed issued transaction
    * @param t transaction
    * @return true if valid, false otherwise
    */
  def verifyTransaction(t:Transaction):Boolean = {
    sig.verify(t._6,t._2.data++t._3.toByteArray++t._4.data++serialize(t._5),t._1.data.take(sig.KeyLength))
  }

  /**
    * sign a transaction to be issued
    * @param sk_s sig private key
    * @param pk_s sig public key
    * @param pk_r sig public key of recipient
    * @param delta transfer amount
    * @param txCounter transaction number
    * @return signed transaction
    */
  def signTransaction(sk_s:PrivateKey, pk_s:PublicKeyW, pk_r:PublicKeyW, delta:BigInt, txCounter:Int): Transaction = {
    val sid:Sid = hash(rng.nextString(64))
    val trans:Transaction = (pk_s,pk_r,delta,sid,txCounter,sig.sign(sk_s,pk_r.data++delta.toByteArray++sid.data++serialize(txCounter)))
    trans
  }

  /**
    * apply each block in chain to passed local state
    * @param ls old local state to be updated
    * @param c chain of block ids
    * @return updated localstate
    */
  def updateLocalState(ls:State, c:Chain): State = {
    var nls:State = ls
    for (id <- c) {
      getBlock(id) match {
        case b:Block => {
          val (_,ledger:Ledger,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey,_,_) = b
          val (pk_vrf,_,_,pk_sig,_) = cert
          val pk_f:PublicKeyW = ByteArrayWrapper(pk_sig++pk_vrf++pk_kes)
          var validForger = true
          if (slot == 0) {
            for (entry <- ledger) {
              entry match {
                case box:Box => {
                  if (verifyBox(box)) {
                    box._1 match {
                      case entry:(ByteArrayWrapper,PublicKeyW,BigInt) => {
                        if (entry._1 == genesisBytes) {
                          val delta = entry._3
                          val netStake:BigInt = 0
                          val newStake:BigInt = netStake + delta
                          val pk_g:PublicKeyW = entry._2
                          if(nls.keySet.contains(pk_g)) nls -= pk_g
                          nls += (pk_g -> (newStake,true,0))
                        }
                      }
                      case _ =>
                    }
                  }
                }
                case _ =>
              }
            }
          }
          ledger.head match {
            case box:Box => {
              if (verifyBox(box)) {
                box._1 match {
                  case entry:(ByteArrayWrapper,BigInt) => {
                    val delta = entry._2
                    if (entry._1 == forgeBytes && delta == BigDecimal(forgerReward).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt) {
                      if (nls.keySet.contains(pk_f)) {
                        val netStake: BigInt = nls(pk_f)._1
                        val txC:Int = nls(pk_f)._3
                        val newStake: BigInt = netStake + BigDecimal(forgerReward).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
                        nls -= pk_f
                        nls += (pk_f -> (newStake,true,txC))
                      } else {
                        validForger = false
                      }
                    } else {
                      validForger = false
                    }
                  }
                  case _ => validForger = false
                }
              } else {
                validForger = false
              }
            }
            case _ => validForger = false
          }

          if (validForger) {
            for (entry <- ledger.tail) {
              entry match {
                case trans:Transaction => {
                  nls = applyTransaction(nls,trans,pk_f)
                }
                case _ =>
              }
            }
          }
        }
        case _ =>
      }
    }
    nls
  }

  /**
    * applies an individual transaction to local state
    * @param ls old local state to be updated
    * @param trans transaction to be applied
    * @param pk_f sig public key of the forger
    * @return updated localstate
    */
  def applyTransaction(ls:State, trans:Transaction, pk_f:PublicKeyW): State = {
    var nls:State = ls
    if (verifyTransaction(trans)) {
      val pk_s:PublicKeyW = trans._1
      val pk_r:PublicKeyW = trans._2
      val validSender = nls.keySet.contains(pk_s)
      val txC_s:Int = nls(pk_s)._3
      if (validSender && trans._5 >= txC_s) {
        val delta:BigInt = trans._3
        val fee = BigDecimal(delta.toDouble*transactionFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
        val validRecip = nls.keySet.contains(pk_r)
        val validFunds = nls(pk_s)._1 >= delta
        if (validRecip && validFunds) {
          if (pk_s == pk_r && pk_s != pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val f_net:BigInt = nls(pk_f)._1
            val f_txC:Int = nls(pk_f)._3
            val s_new: BigInt = s_net - fee
            val f_new: BigInt = f_net + fee
            nls -= pk_s
            nls -= pk_f
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_f -> (f_new,true,f_txC))
          } else if (pk_s == pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val s_new: BigInt = s_net - delta + fee
            val r_new: BigInt = r_net + delta - fee
            nls -= pk_s
            nls -= pk_r
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,r_txC))
          } else if (pk_r == pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta
            nls -= pk_s
            nls -= pk_r
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,r_txC))
          } else if (!nls.keySet.contains(pk_f)) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta - fee
            nls -= pk_s
            nls -= pk_r
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,r_txC))
          } else {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val f_net:BigInt = nls(pk_f)._1
            val f_txC:Int = nls(pk_f)._3
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta - fee
            val f_new: BigInt = f_net + fee
            nls -= pk_s
            nls -= pk_r
            nls -= pk_f
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,r_txC))
            nls += (pk_f -> (f_new,true,f_txC))
          }
        } else if (validFunds) {
          if (pk_s == pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = 0
            val s_new: BigInt = s_net - delta + fee
            val r_new: BigInt = r_net + delta - fee
            nls -= pk_s
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,0))
          } else if (!nls.keySet.contains(pk_f)) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = 0
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta - fee
            nls -= pk_s
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,0))
          } else {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = 0
            val f_net:BigInt = nls(pk_f)._1
            val f_txC = nls(pk_f)._3
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta - fee
            val f_new: BigInt = f_net + fee
            nls -= pk_s
            nls -= pk_f
            nls += (pk_s -> (s_new,true,trans._5+1))
            nls += (pk_r -> (r_new,true,0))
            nls += (pk_f -> (f_new,true,f_txC))
          }
        }
      }
    }
    nls
  }

  /**
    * collects all transaction on the ledger of each block in the passed chain and adds them to the buffer
    * @param c chain to collect transactions
    */
  def collectLedger(c:Chain): Unit = {
    for (id <- c) {
      getBlock(id) match {
        case b:Block => {
          val ledger:Ledger = b._2
          for (entry <- ledger.tail) {
            entry match {
              case trans:Transaction => {
                if (!memPool.keySet.contains(trans._4)) {
                  if (verifyTransaction(trans)) memPool += (trans._4->trans)
                }
              }
              case _ =>
            }
          }
        }
        case _ =>
      }
    }
  }

  /**
    * removes transactions from the buffer that have a tx counter lower than the localstate tx counter
    */
  def updateBuffer: Unit = {
    for (state <- localState) {
      for (entry <- memPool) {
        if (state._1 == entry._2._1) {
          if (entry._2._5 < state._2._3) {
            memPool -= entry._1
          }
        }
      }
    }
  }

  /**
    * sorts buffer and adds transaction to ledger during block forging
    * @param pkw public key triad of forger
    * @return list of transactions
    */
  def chooseLedger(pkw:PublicKeyW): Ledger = {
    var ledger: Ledger = List()
    var ls: State = localState
    val sortedBuffer = ListMap(memPool.toSeq.sortWith(_._2._5 < _._2._5):_*)
    for (entry<-sortedBuffer) {
      if (entry._2._5 >= ls(entry._2._1)._3) {
        ls = applyTransaction(ls,entry._2,pkw)
      }
      ledger ::= entry._2
    }
    ledger.reverse
  }

  /**
    * Verify diffused strings with public key included in the string
    * @param value string to be checked
    * @return true if signature is valid, false otherwise
    */
  def verifyStamp(value: String): Boolean = {
    val values: Array[String] = value.split(";")
    val m = values(0) + ";" + values(1) + ";" + values(2) + ";" + values(3)
    sig.verify(hex2bytes(values(4)), serialize(m), hex2bytes(values(0)))
  }

  /**
    * utility for timing execution of methods
    * @param block any execution block
    * @tparam R
    * @return
    */
  def time[R](block: => R): R = {
    if (timingFlag && holderIndex == 0) {
      val t0 = System.nanoTime()
      val result = block // call-by-name
      val t1 = System.nanoTime()
      val outTime = (t1 - t0)*1.0e-9
      val tString = "%6.6f".format(outTime)
      println("Elapsed time: " + tString + " s")
      result
    } else {
      block
    }
  }
}
