package crypto.ouroboros

import akka.actor.ActorRef
import akka.actor._
import akka.pattern.ask
import akka.util.Timeout

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration._
import scala.language.postfixOps
import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

import bifrost.crypto.hash.FastCryptographicHash
import crypto.Ed25519vrf.Ed25519VRF
import crypto.crypto.malkinKES.MalkinKES
import crypto.crypto.malkinKES.MalkinKES.{MalkinKey, MalkinSignature}
import scorex.crypto.signatures.Curve25519
import scala.math.BigInt

trait obFunctions {
  type Eta = Array[Byte]
  type Sig = Array[Byte]
  type Slot = Int
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
  type Sid = Array[Byte]
  type PublicKeys = (PublicKey,PublicKey,PublicKey)
  type Party = List[PublicKeys]
  type PrivateKey = Array[Byte]
  type Hash = Array[Byte]
  type Pi = Array[Byte]
  type Tx = (Array[Byte],Sid,Sig,PublicKey)
  type Transfer = (PublicKey,PublicKey,BigInt,Sid)
  type State = Map[Tx,BigInt]
  type LocalState = Map[String,BigInt]
  type MemPool = List[Transfer]
  type Tr = Double
  type Cert = (PublicKey,Rho,Pi,PublicKey,Party,Tr)
  type Block = (Hash,State,Slot,Cert,Rho,Pi,MalkinSignature,PublicKey)
  type Chain = List[Block]
  val f_s = 0.9
  val forgerReward = BigDecimal(1.0e8).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
  val transferFee = 0.01
  val confirmationDepth = 10
  val epochLength = 3*confirmationDepth
  val initStakeMax = 1.0e9
  val waitTime = 2 seconds
  val timingFlag = true
  val performanceFlag = false
  val printFlag = true
  val dataOutFlag = true
  val dataOutInterval = 10
  val forgeBytes ="FORGER_REWARD".getBytes
  val transferBytes = "TRANSFER".getBytes
  val genesisBytes = "GENESIS".getBytes
  val keyLength = Curve25519.KeyLength+Ed25519VRF.KeyLength+MalkinKES.KeyLength

  def uuid: String = java.util.UUID.randomUUID.toString

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
    var out: Chain = List()
    var t_lower:Int = 0
    var t_upper:Int = 0
    if (t1>0) t_lower = t1
    if (t2>0) t_upper = t2
    for (b <- c) {
      if(b._3 <= t_upper && b._3 >= t_lower) {out = out++List(b)}
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


  def setParty(s:String): Party = {
    val members = s.split("\n")
    var party:Party = List()
    for (member<-members){
      val values = member.split(";")
      party = party++List((hex2bytes(values(0)),hex2bytes(values(1)),hex2bytes(values(2))))
    }
    party
  }

  /**
    * Verifiable string for communicating between stakeholders
    * @param str data to be diffused
    * @param id holder identification information
    * @param sk_sig holder signature secret key
    * @return string to be diffused
    */
  def diffuse(str: String,id: String,sk_sig: PrivateKey): String = {
    str+";"+id+";"+bytes2hex(Curve25519.sign(sk_sig,serialize(str+";"+id)))
  }

  def signTx(data: Array[Byte],id:Sid,sk_sig: Sig,pk_sig: PublicKey): Tx = {
    (data,id,Curve25519.sign(sk_sig,data++id),pk_sig)
  }

  def verifyTx(tx:Tx): Boolean = {
    Curve25519.verify(tx._3,tx._1++tx._2,tx._4)
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
    * Sends commands one by one to list of stakeholders, except ref given by holderId
    * @param holderId actor not to send
    * @param holders actor list
    * @param command object to be sent
    */
  def send(holderId:String, holders:List[ActorRef],command: Any) = {
    implicit val timeout = Timeout(waitTime)
    for (holder <- holders){
      if (s"${holder.path}" != holderId) {
        val future = holder ? command
        val result = Await.result(future, timeout.duration)
        assert(result == "done")
      }
    }
  }

  /**
    * Block verify using key evolving signature
    * @param b input block
    * @returnt true if signature is valid, false otherwise
    */
  def verifyBlock(b:Block): Boolean = {
    val (hash, state, slot, cert, rho, pi, sig, pk_kes) = b
    val (pk_vrf,_,_,pk_sig,party,_) = cert
    (MalkinKES.verify(pk_kes,hash++serialize(state)++serialize(slot)++serialize(cert)++rho++pi,sig,slot)
      && serialize(party.head).deep == serialize((pk_sig,pk_vrf,pk_kes)).deep
      )
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
      var i = 0
      val t = c.head._3
      var ep = t / epochLength
      var stakingParty = c.head._4._5
      var alpha_Ep = 0.0
      var tr_Ep = 0.0
      var eta_Ep = eta(c, ep)

      for (block <- c.tail) {
        val block0 = c(i)
        val (hash, _, slot, cert, rho, pi, _, pk_kes) = block0
        val (pk_vrf, y, pi_y, pk_sig, party, tr_c) = cert
        if (slot < ep * epochLength + 1) {
          stakingParty = party
          ep -= 1
          eta_Ep = eta(c.drop(i), ep)
        }
        alpha_Ep = relativeStake(party, (pk_sig,pk_vrf,pk_kes), c, ep * epochLength + 1)
        tr_Ep = phi(alpha_Ep, f_s)
        bool &&= (
          FastCryptographicHash(serialize(block)).deep == hash.deep
            && verifyBlock(block0)
            && block._3 < block0._3
            && Ed25519VRF.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("NONCE"), pi)
            && Ed25519VRF.vrfProofToHash(pi).deep == rho.deep
            && Ed25519VRF.vrfVerify(pk_vrf, eta_Ep ++ serialize(slot) ++ serialize("TEST"), pi_y)
            && Ed25519VRF.vrfProofToHash(pi_y).deep == y.deep
            && tr_Ep == tr_c
            && compare(y, tr_Ep)
          )
        i += 1
      }
      bool && FastCryptographicHash(serialize(c.last)).deep == gh.deep
    } else { true }
  }

  /**
    * Verify chain using key evolving siganture, VRF proofs, and hash rule
    * @param c chain to be verified
    * @param gh genesis block hash
    * @param prefix index to verify up to
    * @return true if chain is valid, false otherwise
    */
  def verifyChain(c:Chain, gh:Hash,prefix:Int): Boolean = {
    if (!performanceFlag) {
      var bool = true
      var i = 0
      val t = c.head._3
      var ep = t/epochLength
      var stakingParty = c.head._4._5
      var alpha_Ep = 0.0
      var tr_Ep = 0.0
      var eta_Ep = eta(c,ep)

      for (block <- c.tail.take(prefix+1) ) {
        val block0 = c(i)
        val (hash, _, slot, cert, rho, pi, _, pk_kes) = block0
        val (pk_vrf,y,pi_y,pk_sig,party,tr_c) = cert
        if (slot<ep*epochLength+1){
          stakingParty = party
          ep-=1
          eta_Ep = eta(c.drop(i),ep)
        }
        alpha_Ep = relativeStake(party,(pk_sig,pk_vrf,pk_kes),c,ep*epochLength+1)
        tr_Ep = phi(alpha_Ep,f_s)
        bool &&= (
          FastCryptographicHash(serialize(block)).deep == hash.deep
            && verifyBlock(block0)
            && block._3<block0._3
            && Ed25519VRF.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("NONCE"),pi)
            && Ed25519VRF.vrfProofToHash(pi).deep == rho.deep
            && Ed25519VRF.vrfVerify(pk_vrf,eta_Ep++serialize(slot)++serialize("TEST"),pi_y)
            && Ed25519VRF.vrfProofToHash(pi_y).deep == y.deep
            && tr_Ep == tr_c
            && compare(y,tr_Ep)
          )
        i+=1
      }
      bool && FastCryptographicHash(serialize(c.last)).deep == gh.deep
    } else { true }
  }


  /**
    * Gets the relative stake, alpha, of the stakeholder
    * @param party string containing all stakeholders participating in the round
    * @param holderKey stakeholder public key
    * @param chain chain containing stakeholders transactions
    * @param t current time slot
    * @return alpha, between 0.0 and 1.0
    */
  def relativeStake(party:Party,holderKey:PublicKeys,chain:Chain,t:Int): Double = {
    var holderStake = BigInt(0)
    var netStake = BigInt(0)
    val ep = t/epochLength
    val sc = subChain(chain,0,ep*epochLength-epochLength)
    for (block<-sc) {
      val state = block._2
      for (entry <- state) {
        val (tx,delta) = entry
        if(verifyTx(tx)) {
          val txPk:PublicKey = tx._4
          if (txPk.deep == holderKey._1.deep || tx._1.drop(genesisBytes.length).deep == (holderKey._1++holderKey._2++holderKey._3).deep) {holderStake += delta}
          for (member<-party) {
            if(member._1.deep == txPk.deep || (member._1++member._2++member._3).deep == tx._1.drop(genesisBytes.length).deep){netStake += delta}
          }
        }
      }
    }
    holderStake.toDouble/netStake.toDouble
  }

  def relativeStake(party:Party,holderKeys:PublicKeys,ls:LocalState): Double = {
    var netStake = BigInt(0)
    var holderStake = BigInt(0)
    for (member <- party) {
      val memberKey = bytes2hex(member._1++member._2++member._3)
      if (ls.keySet.contains(memberKey)) netStake += ls(memberKey)
    }
    val holderKey = bytes2hex(holderKeys._1++holderKeys._2++holderKeys._3)
    if (ls.keySet.contains(holderKey)) holderStake = ls(holderKey)
    if (netStake > 0) {
      holderStake.toDouble / netStake.toDouble
    } else {
      0.0
    }
  }

  def updateLocalState(ls:LocalState,c:Chain): LocalState = {
    var nls:LocalState = ls
    for (b <- c.reverse) {
      val (_,state:State,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey) = b
      val (pk_vrf,_,_,pk_sig,_,_) = cert
      for (entry <- state) {
        val (tx:Tx,delta:BigInt) = entry
        if (verifyTx(tx)) {
          val (data:Array[Byte],_,_,pk_tx:PublicKey) = tx
          val pk_f = bytes2hex(pk_sig++pk_vrf++pk_kes)
          val validForger:Boolean =  pk_tx.deep == pk_sig.deep

          if (data.deep == forgeBytes.deep && validForger) {
            if (nls.keySet.contains(pk_f)) {
              val netStake: BigInt = nls(pk_f)
              val newStake: BigInt = netStake + delta
              nls -= pk_f
              nls += (pk_f -> newStake)
            } else {
              val netStake: BigInt = BigInt(0)
              val newStake: BigInt = netStake + delta
              nls += (pk_f -> newStake)
            }
          }

          if (data.take(genesisBytes.length).deep == genesisBytes.deep && slot == 0) {
            val netStake:BigInt = BigInt(0)
            val newStake:BigInt = netStake + delta
            val pk_g = bytes2hex(data.drop(genesisBytes.length))
            if(nls.keySet.contains(pk_g)) nls -= pk_g
            nls += (pk_g -> newStake)
          }

          if (data.take(transferBytes.length).deep == transferBytes.deep && validForger) {
            val pk_s = bytes2hex(data.slice(transferBytes.length,transferBytes.length+keyLength))
            val pk_r = bytes2hex(data.slice(transferBytes.length+keyLength,transferBytes.length+2*keyLength))
            val validSender = nls.keySet.contains(pk_s)
            if (validSender && nls.keySet.contains(pk_r) && nls(pk_s) >= delta) {
              val s_net:BigInt = nls(pk_s)
              val r_net:BigInt = nls(pk_r)
              val f_net:BigInt = nls(pk_f)
              val s_new:BigInt = s_net - delta
              val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
              val r_new:BigInt = r_net + delta - fee
              val f_new:BigInt = f_net + fee
              nls -= pk_s
              nls -= pk_r
              nls -= pk_f
              nls += (pk_s -> s_new)
              nls += (pk_r -> r_new)
              nls += (pk_f -> f_new)
            } else if (validSender && nls(pk_s) >= delta) {
              val s_net:BigInt = nls(pk_s)
              val r_net:BigInt = BigInt(0)
              val f_net:BigInt = nls(pk_f)
              val s_new:BigInt = s_net - delta
              val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
              val r_new:BigInt = r_net + delta - fee
              val f_new:BigInt = f_net + fee
              nls -= pk_s
              nls -= pk_f
              if (s_new > 0) nls += (pk_s -> s_new)
              nls += (pk_r -> r_new)
              nls += (pk_f -> f_new)
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
      val (_,state:State,slot:Slot,cert:Cert,_,_,_,pk_kes:PublicKey) = b
      val (pk_vrf,_,_,pk_sig,_,_) = cert
      for (entry <- state) {
        val (tx:Tx,delta:BigInt) = entry
        if (verifyTx(tx)) {
          val (data:Array[Byte],txId:Sid,_,pk_tx:PublicKey) = tx
          val pk_f = bytes2hex(pk_sig++pk_vrf++pk_kes)
          val validForger:Boolean = pk_tx.deep == pk_sig.deep
          if (data.deep == forgeBytes.deep && validForger) {
            val netStake:BigInt = nls(pk_f)
            val newStake:BigInt = netStake - delta
            nls -= pk_f
            if (newStake > 0) nls += (pk_f -> newStake)
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
            if (validSender && validRecip) {
              val s_net:BigInt = nls(pk_s)
              val r_net:BigInt = nls(pk_r)
              val f_net:BigInt = nls(pk_f)
              val s_new:BigInt = s_net + delta
              val fee = BigDecimal(delta.toDouble*transferFee).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
              val r_new:BigInt = r_net - delta + fee
              val f_new:BigInt = f_net - fee
              nls -= pk_s
              nls -= pk_r
              nls -= pk_f
              if (s_new > 0) nls += (pk_s -> s_new)
              if (r_new > 0) nls += (pk_r -> r_new)
              if (f_new > 0) nls += (pk_f -> f_new)
              val transfer:Transfer = (hex2bytes(pk_s),hex2bytes(pk_r),delta,txId)
              nmem ++= List(transfer)
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
      Curve25519.verify(hex2bytes(values(4)), serialize(m), hex2bytes(values(0)))
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


  /**
    * Byte serialization
    * @param value any object to be serialized
    * @return byte array
    */
  def serialize(value: Any): Array[Byte] = {
    val stream: ByteArrayOutputStream = new ByteArrayOutputStream()
    val oos = new ObjectOutputStream(stream)
    oos.writeObject(value)
    oos.close()
    stream.toByteArray
  }

  /**
    * Deserialize a byte array that was serialized with serialize
    * @param bytes byte array processed with serialize
    * @return original object
    */
  def deserialize(bytes: Array[Byte]): Any = {
    val ois = new ObjectInputStream(new ByteArrayInputStream(bytes))
    val value = ois.readObject
    ois.close()
    value
  }


  def bytes2hex(b: Array[Byte]): String = {
    b.map("%02x" format _).mkString
  }

  def hex2bytes(hex: String): Array[Byte] = {
    if (hex.contains(" ")) {
      hex.split(" ").map(Integer.parseInt(_, 16).toByte)
    } else if (hex.contains("-")) {
      hex.split("-").map(Integer.parseInt(_, 16).toByte)
    } else {
      hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
    }
  }

  def containsDuplicates(s:Map[String,String]):Boolean = {
    var s1:List[String] = List()
    var s2:List[String] = List()
    for (entry <- s) {
      s1 ++= List(entry._1)
      s2 ++= List(entry._2)
    }
    (s1.distinct.size != s1.size) && (s2.distinct.size != s2.size)
  }

  def time[R](block: => R,id:Int): R = {
    if (timingFlag && id == 0) {
      val t0 = System.nanoTime()
      val result = block // call-by-name
      val t1 = System.nanoTime()
      val outTime = (t1 - t0)*1.0e-9
      val tString = "%6.6f".format(outTime)
      println("Elapsed time: "+tString+" s")
      result
    } else {
      block
    }
  }

}
