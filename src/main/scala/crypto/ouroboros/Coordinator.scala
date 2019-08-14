package crypto.ouroboros

import java.io.{BufferedWriter, FileWriter}
import java.io.File
import java.time.Instant
import java.time.temporal.ChronoUnit

import akka.actor.{Actor, ActorRef, PoisonPill, Props, Timers}
import bifrost.crypto.hash.FastCryptographicHash
import io.circe.Json
import io.circe.syntax._
import io.iohk.iodb.ByteArrayWrapper
import scorex.crypto.encode.Base58

import scala.reflect.io.Path
import scala.util.{Try,Random}
import scala.sys.process._

/**
  * Coordinator actor that initializes the genesis block and instantiates the staking party,
  * sends messages to participants to execute a round
  */
class Coordinator extends Actor
  with Timers
  with obMethods
  with coordinatorVars {
  val coordId = s"${self.path}"
  val sys:SystemLoadMonitor = new SystemLoadMonitor
  var loadAverage = Array.fill(numAverageLoad){0.0}
  var genBlock:Block = _

  private case object timerKey
  if (randomFlag) {
    rng = new Random(BigInt(FastCryptographicHash(uuid+"coord")).toLong)
  } else {
    rng = new Random(BigInt(FastCryptographicHash(inputSeed+"coord")).toLong)
  }

  def receive: Receive = {
    /**populates the holder list with stakeholder actor refs
      * This is the F_init functionality */
    case Populate => {
      println(s"Epoch Length = $epochLength")
      println(s"Delta = $delta_s")
      println("Populating")
      if (randomFlag) {
        routerRef = context.actorOf(Router.props(FastCryptographicHash(newSeed+"router")), "Router")
      } else {
        routerRef = context.actorOf(Router.props(FastCryptographicHash(inputSeed+"router")), "Router")
      }
      var i = -1
      holders = List.fill(numHolders){
        i+=1
        if (randomFlag) {
          context.actorOf(Stakeholder.props(FastCryptographicHash(newSeed+i.toString)), "Holder:" + bytes2hex(FastCryptographicHash(newSeed+i.toString)))
        } else {
          context.actorOf(Stakeholder.props(FastCryptographicHash(inputSeed+i.toString)), "Holder:" + bytes2hex(FastCryptographicHash(inputSeed+i.toString)))
        }
      }
      println("Sending holders list")
      sendAssertDone(List(routerRef),holders)
      sendAssertDone(holders,holders)
      println("Sending holders coordinator ref")
      sendAssertDone(holders,RouterRef(routerRef))
      sendAssertDone(holders,CoordRef(self))
      println("Getting holder keys")
      genKeys = collectKeys(holders,RequestKeys,genKeys)
      assert(!containsDuplicates(genKeys))
      println("Forge Genesis Block")
      genBlock = forgeGenBlock
      println("Send GenBlock")
      sendAssertDone(holders,GenBlock(genBlock))
    }
    /**tells actors to print their inbox */
    case Inbox => sendAssertDone(holders,Inbox)

    case Run => {
      println("Diffuse Holder Info")
      sendAssertDone(holders,Diffuse)
      println("Starting")
      sendAssertDone(holders,Initialize(L_s))
      println("Run")
      t0 = System.currentTimeMillis()
      sendAssertDone(holders,SetClock(t0))
      for (holder<-rng.shuffle(holders)) {
        holder ! Run
      }
      timers.startPeriodicTimer(timerKey, ReadCommand, commandUpdateTime)
    }

    case GetTime => if (!actorStalled) {
      val t1 = System.currentTimeMillis()-tp
      sender() ! GetTime(t1)
    } else {
      sender() ! GetTime(tp)
    }

    //tells actors to print status */
    case Status => {
      sendAssertDone(holders,Status)
      assert(sharedData.setOfTxs.keySet.size == sharedData.txCounter)
      println("Total Transactions: "+sharedData.setOfTxs.keySet.size.toString)
      sharedData.txCounter = 0
    }

    case Verify => {
      sendAssertDone(holders,Verify)
    }

    case NewDataFile => {
      if(dataOutFlag) {
        val dataPath = Path(dataFileDir)
        Try(dataPath.createDirectory())
        val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")
        fileWriter = new BufferedWriter(new FileWriter(s"$dataFileDir/ouroboros-data-$dateString.data"))
        val fileString = (
          "Holder_number"
            + " t"
            + " alpha"
            + " blocks_forged"
            + " chain_length"
            +" \n"
          )
        fileWriter match {
          case fw: BufferedWriter => {fw.write(fileString)}
          case _ => println("error: file writer not initialized")
        }
      }
    }

    case WriteFile => {
      sender() ! WriteFile(fileWriter)
    }

    case CloseDataFile => if(dataOutFlag) {
      fileWriter match {
        case fw:BufferedWriter => fw.close()
        case _ => println("error: file writer close on non writer object")
      }
    }

    case ReadCommand => {
      if (!actorStalled) {
        val t1 = System.currentTimeMillis()-tp
        t = ((t1 - t0) / slotT).toInt
      } else {
        t = ((tp - t0) / slotT).toInt
      }

      if (new File("/tmp/scorex/test-data/crypto/cmd").exists) {
        println("-----------------------------------------------------------")
        val f = new File("/tmp/scorex/test-data/crypto/cmd")
        val cmd: String = ("cat" #< f).!!
        f.delete
        val cmdList = cmd.split("\n")
        for (line<-cmdList) {
          val com = line.trim.split(" ")
          com(0) match {
            case s:String => {
              if (com.length == 2){
                com(1).toInt match {
                  case i:Int => {
                    if (s == "print") {
                      sharedData.printingHolder = i
                    } else {
                      cmdQueue += (i->s)
                    }
                  }
                  case _ =>
                }
              } else {
                cmdQueue += (t->s)
              }
            }
            case _ =>
          }
        }
      }
      if (cmdQueue.keySet.contains(t)) {
        command(cmdQueue(t))
        cmdQueue -= t
      }

      if (performanceFlag) {
        val newLoad = sys.cpuLoad
        if (newLoad>0.0){
          loadAverage = loadAverage.tail++Array(newLoad)
        }

        if (!actorPaused) {
          val cpuLoad = (0.0 /: loadAverage){_ + _}/loadAverage.length
          if (cpuLoad >= systemLoadThreshold && !actorStalled) {
            tp = System.currentTimeMillis()-tp
            actorStalled = true
          } else if (cpuLoad < systemLoadThreshold && actorStalled) {
            tp = System.currentTimeMillis()-tp
            actorStalled = false
          }
        }
      }

      if (!actorStalled && transactionFlag && t>1 && t<L_s) {
        for (i <- 1 to holders.length){
          val r = rng.nextInt(txDenominator)
          if (r==0) issueTx
        }
      }

      if (sharedData.killFlag || t>L_s+10) {
        timers.cancelAll
        println("exiting")
        fileWriter match {
          case fw:BufferedWriter => fw.close()
          case _ => println("error: file writer close on non writer object")
        }
        context.system.terminate
      }
    }

    case StallActor => {
      if (!actorPaused) {
        actorPaused = true
        if (!actorStalled) {
          actorStalled = true
          tp = System.currentTimeMillis()-tp
        }
      }
      else {
        actorPaused = false
        if (actorStalled) {
          actorStalled = false
          tp = System.currentTimeMillis()-tp
        }
      }
    }

    case _ => println("received unknown message")
  }

  def issueTx: Unit = {
    val holder1 = holders(rng.nextInt(holders.length))
    val holder2 = holders(rng.nextInt(holders.length))
    var delta:BigInt = 0
    if (holder1 != holder2) {
      delta = BigDecimal(maxTransfer*rng.nextDouble).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt
      holder1 ! IssueTx((holderKeys(holder2),delta))
    }
  }

  def command(s:String): Unit = {
    s.trim match {

      case "status" => {
        self ! Status
      }

      case "verify" => self ! Verify

      case "stall" => sendAssertDone(holders,StallActor)

      case "pause" => self ! StallActor

      case "inbox" => sendAssertDone(holders,Inbox)

      case "stall0" => holders(0) ! StallActor

      case "randtx" => if (!transactionFlag) {transactionFlag = true} else {transactionFlag = false}

      case "write" => fileWriter match {
        case fw:BufferedWriter => fw.flush()
        case _ => println("File writer not initialized")
      }

      case "graph" => {
        println("Getting Gossipers")
        gossipersMap = getGossipers(holders)
        val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")
        graphWriter = new BufferedWriter(new FileWriter(s"$dataFileDir/ouroboros-graph-$dateString.graph"))
        graphWriter match {
          case fw:BufferedWriter => {
            var line:String = ""
            for (holder<-holders) {
              line = ""
              for (ref<-holders) {
                if (gossipersMap(holder).contains(ref)) {
                  line = line + "1"
                } else {
                  line = line + "0"
                }
                if (holders.indexOf(ref)!=holders.length-1) {
                  line = line + " "
                }
              }
              fw.write(line+"\n")
            }
            fw.flush()
          }
          case _ =>
        }
        graphWriter match {
          case fw:BufferedWriter => {
            fw.close()
          }
          case _ =>
        }
      }

      case "tree" => {
        var tn = 0
        if (!actorStalled) {
          val t1 = System.currentTimeMillis()-tp
          tn = ((t1 - t0) / slotT).toInt
        } else {
          val t1 = tp
          tn = ((t1 - t0) / slotT).toInt
        }
        getBlockTree(holders(0))
        val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")
        graphWriter = new BufferedWriter(new FileWriter(s"$dataFileDir/ouroboros-graph-$dateString.tree"))
        graphWriter match {
          case fw:BufferedWriter => {
            val json:Json = (0 to tn).toArray.map{
              case i:Int => Map(
                "slot" -> i.asJson,
                "blocks" -> blocks(i).map{
                  case value:(ByteArrayWrapper,Block) => Map(
                    "id" -> Base58.encode(value._1.data).asJson,
                    "pid" -> Base58.encode(getParentId(value._2)._2.data).asJson,
                    "ps" -> getParentId(value._2)._1.asJson
                  ).asJson
                }.asJson,
                "history" -> chainHistory(i).map{
                  case value:BlockId => Map(
                    "id" -> Base58.encode(value._2.data).asJson
                  ).asJson
                }.asJson
              ).asJson
            }.asJson
            fw.write(json.toString)
            fw.flush()

          }
          case _ =>
        }
        graphWriter match {
          case fw:BufferedWriter => {
            fw.close()
          }
          case _ =>
        }
      }

      case "kill" => {
        sendAssertDone(holders,StallActor)
        for (holder<-holders){ holder ! PoisonPill}
        sharedData.killFlag = true
        self ! CloseDataFile
        context.system.terminate
      }

      case "split" => {
        parties = List()
        val (holders1,holders2) = rng.shuffle(holders).splitAt(rng.nextInt(holders.length-2)+1)
        println("Splitting Party into groups of "+holders1.length.toString+" and "+holders2.length.toString)
        sendAssertDone(holders1,Party(holders1,true))
        sendAssertDone(holders1,Diffuse)
        sendAssertDone(holders2,Party(holders2,true))
        sendAssertDone(holders2,Diffuse)
        parties ::= holders1
        parties ::= holders2
        gossipersMap = getGossipers(holders)
      }

      case "split_stake" => {
        val stakingState:State = getStakingState(holders(0))
        val netStake:BigInt = {
          var out:BigInt = 0
          for (holder<-holders){
            out += stakingState(holderKeys(holder))._1
          }
          out
        }
        var holders1:List[ActorRef] = List()
        var net1:BigInt = 0
        var holders2:List[ActorRef] = List()
        var net2:BigInt = 0
        for (holder <- rng.shuffle(holders)) {
          val holderStake = stakingState(holderKeys(holder))._1
          if (net1<net2) {
            net1 += holderStake
            holders1 ::= holder
          } else {
            net2 += holderStake
            holders2 ::= holder
          }
        }
        val alpha1 = net1.toDouble/netStake.toDouble
        val alpha2 = net2.toDouble/netStake.toDouble
        val numh1 = holders1.length
        val numh2 = holders2.length

        parties = List()

        println(s"Splitting Stake to $alpha1 and $alpha2 with $numh1 and $numh2 holders")
        sendAssertDone(holders1,Party(holders1,true))
        sendAssertDone(holders1,Diffuse)
        sendAssertDone(holders2,Party(holders2,true))
        sendAssertDone(holders2,Diffuse)
        parties ::= holders1
        parties ::= holders2
        gossipersMap = getGossipers(holders)
      }

      case "bridge" => {
        parties = List()
        val (holders1,holders2) = rng.shuffle(holders).splitAt(rng.nextInt(holders.length-3)+2)
        println("Bridging Party into groups of "+holders1.length.toString+" and "+holders2.length.toString)
        val commonRef = holders1.head
        sendAssertDone(holders,Party(List(),true))
        sendAssertDone(List(commonRef),Party(holders,false))
        sendAssertDone(List(commonRef),Diffuse)
        sendAssertDone(holders1.tail,Party(holders1,false))
        sendAssertDone(holders1.tail,Diffuse)
        sendAssertDone(holders2,Party(commonRef::holders2,false))
        sendAssertDone(holders2,Diffuse)
        parties ::= holders1
        parties ::= holders2
        gossipersMap = getGossipers(holders)
      }

      case "bridge_stake" => {
        parties = List()
        val stakingState:State = getStakingState(holders(0))
        val netStake:BigInt = {
          var out:BigInt = 0
          for (holder<-holders){
            out += stakingState(holderKeys(holder))._1
          }
          out
        }
        var holders1:List[ActorRef] = List()
        var net1:BigInt = 0
        var holders2:List[ActorRef] = List()
        var net2:BigInt = 0
        for (holder <- rng.shuffle(holders)) {
          val holderStake = stakingState(holderKeys(holder))._1
          if (net1<net2) {
            net1 += holderStake
            holders1 ::= holder
          } else {
            net2 += holderStake
            holders2 ::= holder
          }
        }
        val alpha1 = net1.toDouble/netStake.toDouble
        val alpha2 = net2.toDouble/netStake.toDouble
        val numh1 = holders1.length
        val numh2 = holders2.length

        parties = List()

        println(s"Bridging Stake to $alpha1 and $alpha2 with $numh1 and $numh2 holders")
        val commonRef = holders1.head
        sendAssertDone(holders,Party(List(),true))
        sendAssertDone(List(commonRef),Party(holders,false))
        sendAssertDone(List(commonRef),Diffuse)
        sendAssertDone(holders1.tail,Party(holders1,false))
        sendAssertDone(holders1.tail,Diffuse)
        sendAssertDone(holders2,Party(commonRef::holders2,false))
        sendAssertDone(holders2,Diffuse)
        parties ::= holders1
        parties ::= holders2
        gossipersMap = getGossipers(holders)
      }

      case "join" => {
        parties = List()
        println("Joining Parties")
        sendAssertDone(holders,Party(holders,true))
        sendAssertDone(holders,Diffuse)
        parties ::= holders
        gossipersMap = getGossipers(holders)
      }

      case "new_holder" => {
        println("Bootstrapping new holder...")
        val i = holders.length
        val newHolder = if (randomFlag) {
          context.actorOf(Stakeholder.props(FastCryptographicHash(newSeed+i.toString)), "Holder:" + bytes2hex(FastCryptographicHash(newSeed+i.toString)))
        } else {
          context.actorOf(Stakeholder.props(FastCryptographicHash(inputSeed+i.toString)), "Holder:" + bytes2hex(FastCryptographicHash(inputSeed+i.toString)))
        }
        holders = holders++List(newHolder)
        sendAssertDone(routerRef,holders)
        sendAssertDone(newHolder,holders)
        sendAssertDone(newHolder,RouterRef(routerRef))
        sendAssertDone(newHolder,CoordRef(self))
        sendAssertDone(newHolder,GenBlock(genBlock))
        val newHolderKeys = collectKeys(List(newHolder),RequestKeys,Map())
        val newHolderKeyW = ByteArrayWrapper(hex2bytes(newHolderKeys(s"${newHolder.path}").split(";")(0))++hex2bytes(newHolderKeys(s"${newHolder.path}").split(";")(1))++hex2bytes(newHolderKeys(s"${newHolder.path}").split(";")(2)))
        holderKeys += (newHolder-> newHolderKeyW)
        sendAssertDone(holders,Party(holders,true))
        sendAssertDone(holders,Diffuse)
        sendAssertDone(newHolder,Initialize(L_s))
        sendAssertDone(newHolder,SetClock(t0))
        newHolder ! Run
      }

      case _ =>
    }
  }

  /**creates genesis block to be sent to all stakeholders */
  def forgeGenBlock: Block = {
    val bn:Int = 0
    val ps:Slot = -1
    val slot:Slot = 0
    val pi:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("NONCE"))
    val rho:Rho = vrf.vrfProofToHash(pi)
    val pi_y:Pi = vrf.vrfProof(sk_vrf,eta0++serialize(slot)++serialize("TEST"))
    val y:Rho = vrf.vrfProofToHash(pi_y)
    val h:Hash = ByteArrayWrapper(eta0)
    val ledger: Ledger = holders.map{
      case ref:ActorRef => {
        val initStake = {initStakeMax*rng.nextDouble}
        val pkw = ByteArrayWrapper(hex2bytes(genKeys(s"${ref.path}").split(";")(0))++hex2bytes(genKeys(s"${ref.path}").split(";")(1))++hex2bytes(genKeys(s"${ref.path}").split(";")(2)))
        holderKeys += (ref-> pkw)
        signBox((genesisBytes, pkw, BigDecimal(initStake).setScale(0, BigDecimal.RoundingMode.HALF_UP).toBigInt), ByteArrayWrapper(FastCryptographicHash(coordId)),sk_sig,pk_sig)
      }
    }
    val cert:Cert = (pk_vrf,y,pi_y,pk_sig,1.0)
    val sig:KesSignature = kes.sign(sk_kes, h.data++serialize(ledger)++serialize(slot)++serialize(cert)++rho++pi++serialize(bn)++serialize(ps))
    (h,ledger,slot,cert,rho,pi,sig,pk_kes,bn,ps)
  }
}

object Coordinator {
  def props: Props = Props(new Coordinator)
}
