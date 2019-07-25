package crypto.ouroboros

import akka.actor.ActorRef
import akka.actor._
import akka.pattern.ask
import akka.util.Timeout

import scala.concurrent.Await
import scala.language.postfixOps
import bifrost.crypto.hash.FastCryptographicHash
import io.iohk.iodb.ByteArrayWrapper

import util.control.Breaks._
import scala.math.BigInt
import scala.util.Random

trait obMethods
  extends obTypes
    with parameters
    with utils {

  //tags for identifying ledger entries
  val forgeBytes = ByteArrayWrapper("FORGER_REWARD".getBytes)
  val genesisBytes = ByteArrayWrapper("GENESIS".getBytes)

  var localChain:Chain = Array()
  var blocks:ChainData = Array()
  var localState:LocalState = Map()
  var stakingState:LocalState = Map()
  var history_state:Array[LocalState] = Array()
  var history_eta:Array[Eta] = Array()
  var memPool:MemPool = Map()
  var holderIndex:Int = -1
  var diffuseSent = false
  val vrf = new obVrf
  val kes = new obKes
  val sig = new obSig

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

  def getParentId(bid:BlockId): Any = {
    getBlock(bid) match {
      case b:Block => (b._10,b._1)
      case _ => 0
    }
  }

  def getParentId(b:Block): BlockId = {
    (b._10,b._1)
  }

  def lastActiveSlot(c:Chain,s:Slot): Slot = {
    var i = s
    while (c(i)._2.data.isEmpty) {
      i-=1
    }
    i
  }

  def getActiveSlots(c:Chain): Int = {
    var i = 0
    for (id<-c) {
      if (!id._2.data.isEmpty) {
        i+=1
      }
    }
    i
  }

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
      //println("H:"+holderIndex.toString+" in:"+bytes2hex(etaP)+"\nNonce Bytes:\n"+bytes2hex(v)+"\n"+"ot:"+bytes2hex(eta_ep))
      eta_ep
    }
  }

  /**
    * returns a subchain containing all blocks in a given time interval
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

  def signTx(data: Any,id:Sid,sk_sig: PrivateKey,pk_sig: PublicKey): Tx = {
    (data,id,sig.sign(sk_sig,serialize(data)++id.data),pk_sig)
  }

  def verifyTx(tx:Tx): Boolean = {
    sig.verify(tx._3,serialize(tx._1)++tx._2.data,tx._4)
  }

  def gossipSet(id:ActorPath,h:List[ActorRef]):List[ActorRef] = {
    var out:List[ActorRef] = List()
    for (holder <- Random.shuffle(h)) {
      if (holder.path != id && out.length < numGossipers) {
        out = holder::out
      }
    }
    out
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holder actor list
    * @param command object to be sent
    */

  def send(holder:ActorRef,command: Any) = {
    holder ! command
  }
  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    */

  def send(holders:List[ActorRef],command: Any) = {
    for (holder <- holders){
      implicit val timeout = Timeout(waitTime)
      val future = holder ? command
      val result = Await.result(future, timeout.duration)
      assert(result == "done")
    }
  }

  /**
    * Sends commands one by one to list of stakeholders
    * @param holders actor list
    * @param command object to be sent
    * @param input map of holder data
    * @return map of holder data
    */

  def sendGenKeys(holders:List[ActorRef],command: Any,input: Map[String,String]): Map[String,String] = {
    var list:Map[String,String] = input
    for (holder <- holders){
      implicit val timeout = Timeout(waitTime)
      val future = holder ? command
      Await.result(future, timeout.duration) match {
        case str:String => {
          if (verifyTxStamp(str)) list = list++Map(s"${holder.path}" -> str)
        }
        case _ => println("error")
      }
    }
    list
  }

  /**
    * Sends commands one by one to shuffled list of stakeholders, except ref given by holderId
    * @param holderId actor not to send
    * @param holders actor list
    * @param command object to be sent
    */

  def send(holderId:ActorPath, holders:List[ActorRef],command: Any) = {
    for (holder <- Random.shuffle(holders)){
      if (holder.path != holderId) {
        holder ! command
      }
    }
  }

  def sendAndWait(holderId:ActorPath,holders:List[ActorRef],command: Tx) = {
    for (holder <- holders){
      implicit val timeout = Timeout(waitTime)
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
    * Verify chain using key evolving siganture, VRF proofs, and hash rule
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
    var stakingState: LocalState = Map()
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
    var stakingState: LocalState = {
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

  def relativeStake(holderKeys:PublicKeys,ls:LocalState): Double = {
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

  def verifyTransfer(t:Transfer):Boolean = {
    sig.verify(t._6,t._2.data++t._3.toByteArray++t._4.data++serialize(t._5),t._1.data.take(sig.KeyLength))
  }

  def signTransfer(sk_s:PrivateKey,pk_s:PublicKeyW,pk_r:PublicKeyW,delta:BigInt,txCounter:Int): Transfer = {
    val sid:Sid = hash(uuid)
    val trans:Transfer = (pk_s,pk_r,delta,sid,txCounter,sig.sign(sk_s,pk_r.data++delta.toByteArray++sid.data++serialize(txCounter)))
    trans
  }

  def updateLocalState(ls:LocalState,c:Chain): LocalState = {
    var nls:LocalState = ls
    for (id <- c) {
      getBlock(id) match {
        case b:Block => {
          val (_,ledger:Ledger,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey,_,_) = b
          val (pk_vrf,_,_,pk_sig,_) = cert
          val pk_f:PublicKeyW = ByteArrayWrapper(pk_sig++pk_vrf++pk_kes)
          var validForger = true
          if (slot == 0) {
            for (tx <- ledger) {
              tx match {
                case tx:Tx => {
                  if (verifyTx(tx)) {
                    tx._1 match {
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
            case tx:Tx => {
              if (verifyTx(tx)) {
                tx._1 match {
                  case entry:(ByteArrayWrapper,BigInt) => {
                    val delta = entry._2
                    if (entry._1 == forgeBytes && delta == forgerReward) {
                      if (nls.keySet.contains(pk_f)) {
                        val netStake: BigInt = nls(pk_f)._1
                        val txC:Int = nls(pk_f)._3
                        val newStake: BigInt = netStake + forgerReward
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
                case trans:Transfer => {
                  nls = applyTransfer(nls,trans,pk_f)
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

  def applyTransfer(ls:LocalState,trans:Transfer,pk_f:PublicKeyW): LocalState = {
    var nls:LocalState = ls
    if (verifyTransfer(trans)) {
      val pk_s:PublicKeyW = trans._1
      val pk_r:PublicKeyW = trans._2
      val validSender = nls.keySet.contains(pk_s)
      val txC_s:Int = nls(pk_s)._3
      if (validSender && trans._5 == txC_s) {
        val delta:BigInt = trans._3
        val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
        val validRecip = nls.keySet.contains(pk_r)
        val validFunds = nls(pk_s)._1 >= delta
        if (validRecip && validFunds) {
          if (pk_s == pk_r && pk_s != pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val f_net:BigInt = nls(pk_f)._1
            val f_txC:Int =nls(pk_f)._3
            val s_new: BigInt = s_net - fee
            val f_new: BigInt = f_net + fee
            nls -= pk_s
            nls -= pk_f
            nls += (pk_s -> (s_new,true,txC_s+1))
            nls += (pk_f -> (f_new,true,f_txC))
          } else if (pk_s == pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val s_new: BigInt = s_net - delta + fee
            val r_new: BigInt = r_net + delta - fee
            nls -= pk_s
            nls -= pk_r
            nls += (pk_s -> (s_new,true,txC_s+1))
            nls += (pk_r -> (r_new,true,r_txC))
          } else if (pk_r == pk_f) {
            val s_net:BigInt = nls(pk_s)._1
            val r_net:BigInt = nls(pk_r)._1
            val r_txC:Int = nls(pk_r)._3
            val s_new: BigInt = s_net - delta
            val r_new: BigInt = r_net + delta
            nls -= pk_s
            nls -= pk_r
            nls += (pk_s -> (s_new,true,txC_s+1))
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
            nls += (pk_s -> (s_new,true,txC_s+1))
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
            nls += (pk_s -> (s_new,true,txC_s+1))
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
            nls += (pk_s -> (s_new,true,txC_s+1))
            nls += (pk_r -> (r_new,true,0))
            nls += (pk_f -> (f_new,true,f_txC))
          }
        }
      }
    }
    nls
  }

  def collectState(c:Chain): Unit = {
    for (id <- c) {
      getBlock(id) match {
        case b:Block => {
          val ledger:Ledger = b._2
          for (entry <- ledger.tail) {
            entry match {
              case trans:Transfer => {
                if (!memPool.keySet.contains(trans._4)) {
                  if (verifyTransfer(trans)) memPool += (trans._4->trans)
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
    * Verify diffused strings with public key included in the string
    * @param value string to be checked
    * @return true if signature is valid, false otherwise
    */

  def verifyTxStamp(value: String): Boolean = {
    val values: Array[String] = value.split(";")
    val m = values(0) + ";" + values(1) + ";" + values(2) + ";" + values(3)
    sig.verify(hex2bytes(values(4)), serialize(m), hex2bytes(values(0)))
  }

  /**
    * Return Id String from Tx stamp
    * @param value stamp to be parsed
    * @return string containing unique info
    */

  def idInfo(value: String): String = {
    val values: Array[String] = value.split(";")
    values(0)+";"+values(1)+";"+values(2)+";"+values(3)
  }

  def idPath(value: String): String = {
    val values: Array[String] = value.split(";")
    values(3)
  }

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
