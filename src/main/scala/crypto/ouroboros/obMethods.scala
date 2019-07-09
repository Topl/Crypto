package crypto.ouroboros

import akka.actor.ActorRef
import akka.actor._
import akka.pattern.ask
import akka.util.Timeout

import scala.concurrent.Await
import scala.language.postfixOps
import bifrost.crypto.hash.FastCryptographicHash
import util.control.Breaks._

import scala.math.BigInt
import scala.util.Random

trait obMethods
  extends obTypes
    with parameters
    with utils {

  val vrf = new obVrf
  val kes = new obKes
  val sig = new obSig

  /**
    * calculates epoch nonce recursively
    * @param c local chain to be verified
    * @param ep epoch derived from time step
    * @return hash nonce
    */

  def eta(c:Chain,ep:Int): Eta = {
    if(ep == 0) {
      c.last._1
    } else {
      var v: Array[Byte] = Array()
      val epcv = subChain(c,ep*epochLength-epochLength,ep*epochLength-epochLength/3)
      val cnext = subChain(c,0,ep*epochLength-epochLength)
      for(block <- epcv) {
        v = v++block._5
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
      c.last._1
    } else {
      var v: Array[Byte] = Array()
      val epcv = subChain(c,ep*epochLength-epochLength,ep*epochLength-epochLength/3)
      for(block <- epcv) {
        v = v++block._5
      }
      val eta_ep = FastCryptographicHash(etaP++serialize(ep)++v)
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
    var out: Chain = Array()
    var t_lower:Int = 0
    var t_upper:Int = 0
    if (t1>0) t_lower = t1
    if (t2>0) t_upper = t2
    breakable {
      for (b <- c) {
        if (b._3 <= t_upper && b._3 >= t_lower) {
          out = out ++ Array(b)
          if (b._3 < t_lower) break
        }
      }
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

  def signTx(data: Array[Byte],id:Sid,sk_sig: Sig,pk_sig: PublicKey): Tx = {
    (data,id,sig.sign(sk_sig,data++id),pk_sig)
  }

  def verifyTx(tx:Tx): Boolean = {
    sig.verify(tx._3,tx._1++tx._2,tx._4)
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

  def send(holders:List[ActorRef],command: Any,input: Map[String,String]): Map[String,String] = {
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

  def send(holderId:String, holders:List[ActorRef],command: Any) = {
    for (holder <- Random.shuffle(holders)){
      if (s"${holder.path}" != holderId) {
        holder ! command
      }
    }
  }

  /**
    * Block verify using key evolving signature
    * @param b input block
    * @returnt true if signature is valid, false otherwise
    */

  def verifyBlock(b:Block): Boolean = {
    val (hash, state, slot, cert, rho, pi, sig, pk_kes, bn,ps) = b
    kes.verify(pk_kes,hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps),sig,slot)
  }

  /**
    * Verify chain using key evolving siganture, VRF proofs, and hash rule
    * @param c chain to be verified
    * @param gh genesis block hash
    * @return true if chain is valid, false otherwise
    */

  def verifyChain(c:Chain, gh:Hash): Boolean = {
    if (!performanceFlag) {
      var bool = true
      var i = c.length-1
      var ep = -1
      var alpha_Ep = 0.0
      var tr_Ep = 0.0
      var eta_Ep:Eta = eta(c,0)
      var stakingState:LocalState = Map()

      bool &&= FastCryptographicHash(serialize(c.last)).deep == gh.deep

      for (block <- c.tail.reverse) {
        i -= 1
        val block0 = c(i)
        val (hash, _, slot, cert, rho, pi, _, pk_kes,bn,ps) = block0
        val (pk_vrf, y, pi_y, pk_sig, tr_c) = cert

        if (slot/epochLength > ep) {
          ep = slot/epochLength
          eta_Ep = eta(c.drop(i), ep, eta_Ep)
          stakingState = updateLocalState(stakingState, subChain(c, (slot / epochLength) * epochLength - 2 * epochLength + 1, (slot / epochLength) * epochLength - epochLength))
          if (ep>0) stakingState = activeStake(stakingState, subChain(c, (slot / epochLength) * epochLength - 10 * epochLength + 1, (slot / epochLength) * epochLength - epochLength))
        }
        alpha_Ep = relativeStake((pk_sig,pk_vrf,pk_kes),stakingState)
        tr_Ep = phi(alpha_Ep, f_s)
        bool &&= (
            FastCryptographicHash(serialize(block)).deep == hash.deep
        && verifyBlock(block0)
        && block._3 == ps
        && block._9+1 == bn
        && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi)
        && vrf.vrfProofToHash(pi).deep == rho.deep
        && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y)
        && vrf.vrfProofToHash(pi_y).deep == y.deep
        && tr_Ep == tr_c
        && compare(y, tr_Ep)
        )
        if(!bool){
          print(slot);print(" ")
          println(Seq(
              FastCryptographicHash(serialize(block)).deep == hash.deep //1
            , verifyBlock(block0) //2
            , block._3 == ps //3
            , block._9+1 == bn //4
            , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("NONCE"),pi) //5
            , vrf.vrfProofToHash(pi).deep == rho.deep //6
            , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("TEST"),pi_y) //7
            , vrf.vrfProofToHash(pi_y).deep == y.deep //8
            , tr_Ep == tr_c //9
            , compare(y,tr_Ep) //10
          ))
        }
      }
      bool
    } else { true }
  }

  /**
    * Verify chain using key evolving signature, VRF proofs, and hash rule
    * @param c chain to be verified
    * @return true if chain is valid, false otherwise
    */

  def verifyChain(c:Chain,ls0:LocalState,eta0:Eta,ep0:Int,ls1:LocalState,eta1:Eta): Boolean = {
    if (!performanceFlag) {
      var bool = true
      var i = c.length-1
      var ep = ep0
      var alpha_Ep = 0.0
      var tr_Ep = 0.0
      var eta_Ep:Eta = eta0
      var stakingState:LocalState = ls0

      for (block <- c.tail.reverse) {
        i -= 1
        val block0 = c(i)
        val (hash, _, slot, cert, rho, pi, _, pk_kes,bn,ps) = block0
        val (pk_vrf, y, pi_y, pk_sig, tr_c) = cert
        if (slot/epochLength > ep0) {
          ep = slot/epochLength
          eta_Ep = eta1
          stakingState = ls1
        } else if (slot/epochLength>ep) {
          ep = slot/epochLength
          eta_Ep = eta(c, ep, eta_Ep)
          stakingState = updateLocalState(stakingState, subChain(c, (slot / epochLength) * epochLength - 2 * epochLength + 1, (slot / epochLength) * epochLength - epochLength))
        }
        alpha_Ep = relativeStake((pk_sig,pk_vrf,pk_kes),stakingState)
        tr_Ep = phi(alpha_Ep, f_s)
        bool &&= (
          FastCryptographicHash(serialize(block)).deep == hash.deep
            && verifyBlock(block0)
            && block._3 == ps
            && block._9+1 == bn
            && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi)
            && vrf.vrfProofToHash(pi).deep == rho.deep
            && vrf.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y)
            && vrf.vrfProofToHash(pi_y).deep == y.deep
            && tr_Ep == tr_c
            && compare(y, tr_Ep)
          )
        if(!bool){
          print(slot);print(" ")
          println(Seq(
            FastCryptographicHash(serialize(block)).deep == hash.deep //1
            , verifyBlock(block0) //2
            , block._3 == ps //3
            , block._9+1 == bn //4
            , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("NONCE"),pi) //5
            , vrf.vrfProofToHash(pi).deep == rho.deep //6
            , vrf.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("TEST"),pi_y) //7
            , vrf.vrfProofToHash(pi_y).deep == y.deep //8
            , tr_Ep == tr_c //9
            , compare(y,tr_Ep) //10
          ))
        }
      }
      bool
    } else { true }
  }


  def relativeStake(holderKeys:PublicKeys,ls:LocalState): Double = {
    var netStake:BigInt = 0
    var holderStake:BigInt = 0
    for (member <- ls.keySet) {
      val (balance,activityIndex) = ls(member)
      if (activityIndex) netStake += balance
    }
    val holderKey = bytes2hex(holderKeys._1++holderKeys._2++holderKeys._3)
    if (ls.keySet.contains(holderKey)){
      val (balance,activityIndex) = ls(holderKey)
      if (activityIndex) holderStake += balance
    }
    if (netStake > 0) {
      holderStake.toDouble / netStake.toDouble
    } else {
      0.0
    }
  }

  def activeStake(ls:LocalState,c:Chain): LocalState = {
    var nls:LocalState = ls
    for (member <- ls.keySet) {
      breakable {
        val (balance, _) = ls(member)
        for (b <- c) {
          val (_, state: State, slot: Slot, cert: Cert, _, _, _, pk_kes: PublicKey,_,_) = b
          val (pk_vrf, _, _, pk_sig, _) = cert
          val pk_f = bytes2hex(pk_sig ++ pk_vrf ++ pk_kes)
          if (pk_f == member && slot>0) {nls -= member; nls += (member -> (balance, true)); break}
          for (entry <- state) {
            val (tx: Tx, _) = entry
            val (data: Array[Byte], _, _, _) = tx
            if (data.take(genesisBytes.length).deep == genesisBytes.deep && slot == 0) {
              val pk_g = bytes2hex(data.drop(genesisBytes.length))
              if (pk_g == member) {nls -= member; nls += (member -> (balance, true)); break}
            }
            if (data.take(transferBytes.length).deep == transferBytes.deep) {
              val pk_s = bytes2hex(data.slice(transferBytes.length, transferBytes.length + keyLength))
              if (pk_s == member) {nls -= member; nls += (member -> (balance, true)); break}
              val pk_r = bytes2hex(data.slice(transferBytes.length + keyLength, transferBytes.length + 2 * keyLength))
              if (pk_r == member) {nls -= member; nls += (member -> (balance, true)); break}
            }
          }
          nls -= member
          nls += (member -> (balance, false))
        }
      }
    }
    nls
  }

  def updateLocalState(ls:LocalState,c:Chain): LocalState = {
    var nls:LocalState = ls
    for (b <- c.reverse) {
      val (_,state:State,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey,_,_) = b
      val (pk_vrf,_,_,pk_sig,_) = cert
      for (entry <- state) {
        val (tx:Tx,delta:BigInt) = entry
        if (verifyTx(tx)) {
          val (data:Array[Byte],_,_,pk_tx:PublicKey) = tx
          val pk_f = bytes2hex(pk_sig++pk_vrf++pk_kes)
          val validForger:Boolean =  pk_tx.deep == pk_sig.deep

          if (data.deep == forgeBytes.deep && validForger) {
            if (nls.keySet.contains(pk_f)) {
              val netStake: BigInt = nls(pk_f)._1
              val newStake: BigInt = netStake + delta
              nls -= pk_f
              nls += (pk_f -> (newStake,true))
            } else {
              val netStake: BigInt = 0
              val newStake: BigInt = netStake + delta
              nls += (pk_f -> (newStake,true))
            }
          }

          if (data.take(genesisBytes.length).deep == genesisBytes.deep && slot == 0) {
            val netStake:BigInt = 0
            val newStake:BigInt = netStake + delta
            val pk_g = bytes2hex(data.drop(genesisBytes.length))
            if(nls.keySet.contains(pk_g)) nls -= pk_g
            nls += (pk_g -> (newStake,true))
          }

          if (data.take(transferBytes.length).deep == transferBytes.deep && validForger) {
            val pk_s = bytes2hex(data.slice(transferBytes.length,transferBytes.length+keyLength))
            val pk_r = bytes2hex(data.slice(transferBytes.length+keyLength,transferBytes.length+2*keyLength))
            val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
            val validSender = nls.keySet.contains(pk_s)
            val validRecip = nls.keySet.contains(pk_r)
            val forgerBalance = nls.keySet.contains(pk_f)
            val validFunds = if(validSender) {nls(pk_s)._1 >= delta} else { false }
            if (validSender && validRecip && validFunds) {
              if (pk_s == pk_r && pk_s != pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new: BigInt = s_net - fee
                val f_new: BigInt = f_net + fee
                nls -= pk_s
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_f -> (f_new,true))
              } else if (pk_s == pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = nls(pk_r)._1
                val s_new: BigInt = s_net - delta + fee
                val r_new: BigInt = r_net + delta - fee
                nls -= pk_s
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
              } else if (pk_r == pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = nls(pk_r)._1
                val s_new: BigInt = s_net - delta
                val r_new: BigInt = r_net + delta
                nls -= pk_s
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
              } else {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = nls(pk_r)._1
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new: BigInt = s_net - delta
                val r_new: BigInt = r_net + delta - fee
                val f_new: BigInt = f_net + fee
                nls -= pk_s
                nls -= pk_r
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
                nls += (pk_f -> (f_new,true))
              }
            } else if (validSender && validFunds) {
              if (pk_s == pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = 0
                val s_new: BigInt = s_net - delta + fee
                val r_new: BigInt = r_net + delta - fee
                nls -= pk_s
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
              } else if (pk_r == pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = 0
                val s_new: BigInt = s_net - delta
                val r_new: BigInt = r_net + delta
                nls -= pk_s
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
              } else {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = 0
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new: BigInt = s_net - delta
                val r_new: BigInt = r_net + delta - fee
                val f_new: BigInt = f_net + fee
                nls -= pk_s
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_r -> (r_new,true))
                nls += (pk_f -> (f_new,true))
              }
            }
          }
        }
      }
    }
    nls
  }

  def revertLocalState(ls: LocalState,c:Chain,mem:MemPool): (LocalState,MemPool) = {
    var nls:LocalState = ls
    var nmem:MemPool = mem
    for (b <- c) {
      val (_,state:State,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey,_,_) = b
      val (pk_vrf,_,_,pk_sig,_) = cert
      for (entry <- state) {
        val (tx:Tx,delta:BigInt) = entry
        if (verifyTx(tx)) {
          val (data:Array[Byte],txId:Sid,_,pk_tx:PublicKey) = tx
          val pk_f = bytes2hex(pk_sig++pk_vrf++pk_kes)
          val validForger:Boolean = pk_tx.deep == pk_sig.deep

          if (data.deep == forgeBytes.deep && validForger) {
            if (nls.keySet.contains(pk_f)) {
              val netStake:BigInt = nls(pk_f)._1
              val newStake:BigInt = netStake - delta
              nls -= pk_f
              if (newStake > 0) nls += (pk_f -> (newStake,true))
            }
          }

          if (data.take(genesisBytes.length).deep == genesisBytes.deep && slot == 0) {
            val pk_g = bytes2hex(data.drop(genesisBytes.length))
            nls -= pk_g
          }

          if (data.take(transferBytes.length).deep == transferBytes.deep && validForger) {
            val pk_s = bytes2hex(data.slice(transferBytes.length,transferBytes.length+keyLength))
            val pk_r = bytes2hex(data.slice(transferBytes.length+keyLength,transferBytes.length+2*keyLength))
            val validSender = nls.keySet.contains(pk_s)
            val validRecip = nls.keySet.contains(pk_r)
            val forgerBalance = nls.keySet.contains(pk_f)
            val validTransfer = pk_s != pk_r
            val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
            if (validSender && validRecip && validTransfer) {
              if (pk_s == pk_r && pk_s != pk_f) {
                val s_net:BigInt = nls(pk_s)._1
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new: BigInt = s_net + fee
                val f_new: BigInt = f_net - fee
                nls -= pk_s
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                nls += (pk_f -> (f_new,true))
              } else if (pk_f == pk_s) {
                val s_net: BigInt = nls(pk_s)._1
                val r_net: BigInt = nls(pk_r)._1
                val s_new: BigInt = s_net + delta - fee
                val r_new: BigInt = r_net - delta + fee
                nls -= pk_s
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                val transfer: Transfer = (hex2bytes(pk_s), hex2bytes(pk_r), delta, txId)
                nmem ++= List(transfer)
              } else if (pk_f == pk_r) {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = nls(pk_r)._1
                val s_new:BigInt = s_net + delta
                val r_new:BigInt = r_net - delta
                nls -= pk_s
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                val transfer:Transfer = (hex2bytes(pk_s),hex2bytes(pk_r),delta,txId)
                nmem ++= List(transfer)
              } else {
                val s_net:BigInt = nls(pk_s)._1
                val r_net:BigInt = nls(pk_r)._1
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new:BigInt = s_net + delta
                val r_new:BigInt = r_net - delta + fee
                val f_new:BigInt = f_net - fee
                nls -= pk_s
                nls -= pk_r
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                if (f_new > 0) nls += (pk_f -> (f_new,true))
                val transfer:Transfer = (hex2bytes(pk_s),hex2bytes(pk_r),delta,txId)
                nmem ++= List(transfer)
              }
            } else if (validRecip && validTransfer) {
              if (pk_f == pk_s) {
                val s_net: BigInt = 0
                val r_net: BigInt = nls(pk_r)._1
                val s_new: BigInt = s_net + delta - fee
                val r_new: BigInt = r_net - delta + fee
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                val transfer: Transfer = (hex2bytes(pk_s), hex2bytes(pk_r), delta, txId)
                nmem ++= List(transfer)
              } else if (pk_f == pk_r) {
                val s_net:BigInt = 0
                val r_net:BigInt = nls(pk_r)._1
                val s_new:BigInt = s_net + delta
                val r_new:BigInt = r_net - delta
                nls -= pk_r
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                val transfer:Transfer = (hex2bytes(pk_s),hex2bytes(pk_r),delta,txId)
                nmem ++= List(transfer)
              } else {
                val s_net:BigInt = 0
                val r_net:BigInt = nls(pk_r)._1
                val f_net:BigInt = {if (forgerBalance) nls(pk_f)._1 else 0}
                val s_new:BigInt = s_net + delta
                val r_new:BigInt = r_net - delta + fee
                val f_new:BigInt = f_net - fee
                nls -= pk_r
                if (forgerBalance) nls -= pk_f
                if (s_new > 0) nls += (pk_s -> (s_new,true))
                if (r_new > 0) nls += (pk_r -> (r_new,true))
                if (f_new > 0) nls += (pk_f -> (f_new,true))
                val transfer:Transfer = (hex2bytes(pk_s),hex2bytes(pk_r),delta,txId)
                nmem ++= List(transfer)
              }
            }
          }
        }
      }
    }
    (nls,nmem)
  }

  /**
    * Verify diffused strings with public key included in the string
    * @param value string to be checked
    * @return true if signature is valid, false otherwise
    */

  def verifyTxStamp(value: String): Boolean = {
    if (!performanceFlag) {
      val values: Array[String] = value.split(";")
      val m = values(0) + ";" + values(1) + ";" + values(2) + ";" + values(3)
      sig.verify(hex2bytes(values(4)), serialize(m), hex2bytes(values(0)))
    } else { true }
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

}
