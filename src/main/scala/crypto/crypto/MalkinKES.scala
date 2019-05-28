package crypto.crypto.malkinKES

import bifrost.crypto.hash.FastCryptographicHash
import org.bouncycastle.math.ec.rfc8032.Ed25519
import scorex.crypto.hash.Sha512
import crypto.crypto.tree.{Tree,Node,Leaf,Empty}
import scala.math.BigInt

object MalkinKES {

  val seedBytes = 32
  val pkBytes = Ed25519.PUBLIC_KEY_SIZE
  val skBytes = Ed25519.SECRET_KEY_SIZE
  val sigBytes = Ed25519.SIGNATURE_SIZE
  val hashBytes = 32

  type MalkinKey = (Tree[Array[Byte]],Tree[Array[Byte]],Array[Byte],Array[Byte],Array[Byte])
  type MalkinSignature = (Array[Byte],Array[Byte],Array[Byte])

  def exp(n: Int): Int = {
    scala.math.pow(2,n).toInt
  }

  def PRNG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val r1 = FastCryptographicHash(k)
    val r2 = FastCryptographicHash(Sha512(r1++k))
    (r1,r2)
  }

  def sKeypairFast(seed: Array[Byte]): Array[Byte] = {
    val sk = FastCryptographicHash(seed)
    var pk = Array.fill(32){0x00.toByte}
    Ed25519.generatePublicKey(sk,0,pk,0)
    sk++pk
  }

  def sPublic(seed: Array[Byte]): Array[Byte] = {
    val sk = FastCryptographicHash(seed)
    var pk = Array.fill(32){0x00.toByte}
    Ed25519.generatePublicKey(sk,0,pk,0)
    pk
  }

  def sPrivate(seed: Array[Byte]): Array[Byte] = {
    FastCryptographicHash(seed)
  }

  def sSign(m: Array[Byte], sk: Array[Byte]): Array[Byte] = {
    var sig: Array[Byte] = Array.fill(sigBytes){0x00.toByte}
    Ed25519.sign(sk,0,m,0,m.length,sig,0)
    sig
  }

  def sVerify(m: Array[Byte], sig: Array[Byte], pk: Array[Byte]): Boolean = {
    Ed25519.verify(sig,0,pk,0,m,0,m.length)
  }

  def sumGetPublicKey(t: Tree[Array[Byte]]): Array[Byte] = {
    t match {
      case n: Node[Array[Byte]] => {
        val pk0 = n.v.slice(seedBytes, seedBytes + pkBytes)
        val pk1 = n.v.slice(seedBytes + pkBytes, seedBytes + 2 * pkBytes)
        FastCryptographicHash(pk0 ++ pk1)
      }
      case l: Leaf[Array[Byte]] => {
        FastCryptographicHash(FastCryptographicHash(l.v.slice(seedBytes, seedBytes + pkBytes))++FastCryptographicHash(l.v.slice(seedBytes, seedBytes + pkBytes)))
      }
      case _ => Array()
    }
  }

  def sumGenerateKey(seed: Array[Byte],i:Int):Tree[Array[Byte]] = {

    def sumKeyGenMerkle(seed: Array[Byte],i:Int): Tree[Array[Byte]] = {
      if (i==0){
        Leaf(seed)
      } else {
        val r = PRNG(seed)
        Node(r._2,sumKeyGenMerkle(r._1,i-1),sumKeyGenMerkle(r._2,i-1))
      }
    }

    def populateLeaf(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
      t match {
        case n: Node[Array[Byte]] => {
          Node(n.v,populateLeaf(n.l),populateLeaf(n.r))
        }
        case l: Leaf[Array[Byte]] => {
          Leaf(l.v++sKeypairFast(l.v))
        }
        case _ => {
          Empty
        }
      }
    }

    def merklePublicKeys(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
      def loop(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
        t match {
          case n: Node[Array[Byte]] => {
            var sk0: Array[Byte] = Array()
            var pk0: Array[Byte] = Array()
            var pk00: Array[Byte] = Array()
            var pk01: Array[Byte] = Array()
            var sk1: Array[Byte] = Array()
            var pk1: Array[Byte] = Array()
            var pk10: Array[Byte] = Array()
            var pk11: Array[Byte] = Array()
            var pk: Array[Byte] = Array()
            var r0: Array[Byte] = Array()
            var r1: Array[Byte] = Array()
            var leftVal: Array[Byte] = Array()
            var rightVal: Array[Byte] = Array()
            var leafLevel = false
            val left = loop(n.l) match {
              case nn: Node[Array[Byte]] => {
                leftVal = nn.v
                nn
              }
              case ll: Leaf[Array[Byte]] => {
                leafLevel = true
                leftVal = ll.v
                ll
              }
            }
            val right = loop(n.r) match {
              case nn: Node[Array[Byte]] => {
                rightVal = nn.v
                nn
              }
              case ll: Leaf[Array[Byte]] => {
                leafLevel = true
                rightVal = ll.v
                ll
              }
            }
            if (leafLevel) {
              r0 = leftVal.slice(0, seedBytes)
              sk0 = leftVal.slice(seedBytes, seedBytes + skBytes)
              pk0 = leftVal.slice(seedBytes + skBytes, seedBytes + skBytes + pkBytes)
              r1 = rightVal.slice(0, seedBytes)
              sk1 = rightVal.slice(seedBytes, seedBytes + skBytes)
              pk1 = rightVal.slice(seedBytes + skBytes, seedBytes + skBytes + pkBytes)
              assert(n.v.deep == r1.deep)
              Node(n.v ++ FastCryptographicHash(pk0) ++ FastCryptographicHash(pk1), Leaf(sk0 ++ pk0), Leaf(sk1 ++ pk1))
            } else {
              pk00 = leftVal.slice(seedBytes, seedBytes + pkBytes)
              pk01 = leftVal.slice(seedBytes + pkBytes, seedBytes + 2 * pkBytes)
              pk10 = rightVal.slice(seedBytes, seedBytes + pkBytes)
              pk11 = rightVal.slice(seedBytes + pkBytes, seedBytes + 2 * pkBytes)
              pk0 = FastCryptographicHash(pk00 ++ pk01)
              pk1 = FastCryptographicHash(pk10 ++ pk11)
              Node(n.v ++ pk0 ++ pk1, left, right)
            }
          }
          case l: Leaf[Array[Byte]] => {
            l
          }
          case _ => {
            Empty
          }
        }
      }
      t match {
        case n: Node[Array[Byte]] => {
          loop(n)
        }
        case l: Leaf[Array[Byte]] => {
          Leaf(l.v.drop(seedBytes))
        }
        case _ => {
          Empty
        }
      }
    }

    def trimTree(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
      t match {
        case n: Node[Array[Byte]] => {
          Node(n.v,trimTree(n.l),Empty)
        }
        case l: Leaf[Array[Byte]] => {
          l
        }
        case _ => {
          Empty
        }
      }
    }

    trimTree(merklePublicKeys(populateLeaf(sumKeyGenMerkle(seed,i))))
  }

  def sumVerifyKeyPair(t: Tree[Array[Byte]], pk:Array[Byte]): Boolean = {

    def loop(t: Tree[Array[Byte]]): Boolean = {
      t match {
        case n: Node[Array[Byte]] =>{
          var pk0:Array[Byte] = Array()
          var pk00:Array[Byte] = Array()
          var pk01:Array[Byte] = Array()
          var pk1:Array[Byte] = Array()
          var pk10:Array[Byte] = Array()
          var pk11:Array[Byte] = Array()
          val left = n.l match {
            case nn: Node[Array[Byte]] => {
              pk00 = nn.v.slice(seedBytes,seedBytes+pkBytes)
              pk01 = nn.v.slice(seedBytes+pkBytes,seedBytes+2*pkBytes)
              pk0 = FastCryptographicHash(pk00++pk01)
              loop(nn) && (pk0.deep == n.v.slice(seedBytes,seedBytes+pkBytes).deep)
            }
            case ll: Leaf[Array[Byte]] => {
              FastCryptographicHash(ll.v.slice(skBytes,skBytes+pkBytes)).deep == n.v.slice(seedBytes,seedBytes+pkBytes).deep
            }
            case _ => true
          }
          val right = n.r match {
            case nn: Node[Array[Byte]] => {
              pk10 = nn.v.slice(seedBytes,seedBytes+pkBytes)
              pk11 = nn.v.slice(seedBytes+pkBytes,seedBytes+2*pkBytes)
              pk1 = FastCryptographicHash(pk10++pk11)
              loop(nn) && (pk1.deep == n.v.slice(seedBytes+pkBytes,seedBytes+2*pkBytes).deep)
            }
            case ll: Leaf[Array[Byte]] => {
              FastCryptographicHash(ll.v.slice(skBytes,skBytes+pkBytes)).deep == n.v.slice(seedBytes+pkBytes,seedBytes+2*pkBytes).deep
            }
            case _ => true
          }
          left && right
        }
        case l: Leaf[Array[Byte]] => FastCryptographicHash(FastCryptographicHash(l.v.slice(skBytes,skBytes+pkBytes))++FastCryptographicHash(l.v.slice(skBytes,skBytes+pkBytes))).deep == pk.deep
        case _ => false
      }
    }

    (pk.deep == sumGetPublicKey(t).deep) && loop(t)
  }

  def sumUpdate(key: Tree[Array[Byte]],t:Int): Tree[Array[Byte]] = {

    def isRightBranch(t: Tree[Array[Byte]]): Boolean = {
      t match {
        case n: Node[Array[Byte]] =>{
          val left = n.l match {
            case n: Node[Array[Byte]] => false
            case l: Leaf[Array[Byte]] => false
            case _ => true
          }
          val right = n.r match {
            case n: Node[Array[Byte]] => isRightBranch(n)
            case l: Leaf[Array[Byte]] => true
            case _ => false
          }
          left && right
        }
        case l: Leaf[Array[Byte]] => false
        case _ => false
      }
    }

    def loop(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
      t match {
        case n: Node[Array[Byte]] => {
          var leftIsEmpty = false
          var leftIsLeaf = false
          var leftIsNode = false
          var leftVal: Array[Byte] = Array()
          var rightIsEmpty = false
          var rightIsLeaf = false
          var rightIsNode = false
          var rightVal: Array[Byte] = Array()

          val left = n.l match {
            case n: Node[Array[Byte]] => leftIsNode = true;leftVal=n.v;n
            case l: Leaf[Array[Byte]] => leftIsLeaf = true;leftVal=l.v;l
            case _ => leftIsEmpty = true; n.l
          }
          val right = n.r match {
            case n: Node[Array[Byte]] => rightIsNode=true;rightVal=n.v;n
            case l: Leaf[Array[Byte]] => rightIsLeaf=true;rightVal=l.v;l
            case _ => rightIsEmpty = true; n.r
          }
          val cutBranch = isRightBranch(left)
          if (rightIsEmpty && leftIsLeaf) {
            //println("right is empty and left is leaf")
            val keyPair = sKeypairFast(n.v.slice(0,seedBytes))
            assert(FastCryptographicHash(keyPair.slice(skBytes,skBytes+pkBytes)).deep == n.v.slice(seedBytes+pkBytes,seedBytes+2*pkBytes).deep)
            Node(n.v,Empty,Leaf(keyPair))
          } else if (cutBranch) {
            //println("cut branch")
            Node(n.v,Empty,sumGenerateKey(n.v.slice(0,seedBytes),n.height-1))
          } else if (leftIsNode && rightIsEmpty) {
            //println("left is node and right is empty")
            Node(n.v,loop(left),Empty)
          } else if (leftIsEmpty && rightIsNode) {
            //println("left is empty and right is node")
            Node(n.v, Empty, loop(right))
          } else if (leftIsEmpty && rightIsLeaf) {
            //println("Error: cut branch failed, left is empty and right is leaf")
            n
          } else if (leftIsEmpty && rightIsEmpty) {
            //println("Error: left and right is empty")
            n
          } else {
            //println("Error: did nothing")
            n
          }
        }
        case l: Leaf[Array[Byte]] => l
        case _ => t
      }
    }

    val keyH = key.height
    val T = exp(key.height)
    val keyTime = sumGetKeyTimeStep(key)

    if (t<T && keyTime < t){
      var tempKey = key
      for(i <- keyTime+1 to t) {
        tempKey = loop(tempKey)
      }
      tempKey
    } else {
      println("Time step error, key not updated")
      println("T: "+T.toString+", key t:"+keyTime.toString+", t:"+t.toString)
      key
    }
  }

  def sumSign(sk: Tree[Array[Byte]],m: Array[Byte],step:Int): Array[Byte] = {
    assert(step == sumGetKeyTimeStep(sk))
    assert(sumVerifyKeyPair(sk,sumGetPublicKey(sk)))
    val stepBytesBigInt = BigInt(step).toByteArray
    val stepBytes = Array.fill(seedBytes-stepBytesBigInt.length){0x00.toByte}++stepBytesBigInt

    def loop(t: Tree[Array[Byte]]): Array[Byte] = {
      t match {
        case n: Node[Array[Byte]] => {
          val left = n.l match {
            case nn: Node[Array[Byte]] => {
              loop(nn)
            }
            case ll: Leaf[Array[Byte]] => {
              sSign(m++stepBytes,ll.v.slice(0,skBytes))++ll.v.slice(skBytes,skBytes+pkBytes)++stepBytes
            }
            case _ => Array()
          }
          val right = n.r match {
            case nn: Node[Array[Byte]] => {
              loop(nn)
            }
            case ll: Leaf[Array[Byte]] => {
              sSign(m++stepBytes,ll.v.slice(0,skBytes))++ll.v.slice(skBytes,skBytes+pkBytes)++stepBytes
            }
            case _ => Array()
          }
          left++right++n.v.slice(seedBytes,seedBytes+2*pkBytes)
        }
        case l: Leaf[Array[Byte]] => {
          sSign(m++stepBytes,l.v.slice(0,skBytes))++l.v.slice(skBytes,skBytes+pkBytes)++stepBytes++FastCryptographicHash(l.v.slice(skBytes,skBytes+pkBytes))++FastCryptographicHash(l.v.slice(skBytes,skBytes+pkBytes))
        }
        case _ => {
          Array()
        }
      }
    }

    loop(sk)
  }

  def sumVerify(pk: Array[Byte],m: Array[Byte],sig: Array[Byte]): Boolean = {
    val pkSeq = sig.drop(sigBytes+pkBytes+seedBytes)
    val stepBytes = sig.slice(sigBytes+pkBytes,sigBytes+pkBytes+seedBytes)
    val step = BigInt(stepBytes)
    var pkLogic = true
    if (step % 2 == 0) {
      pkLogic &= FastCryptographicHash(sig.slice(sigBytes,sigBytes+pkBytes)).deep == pkSeq.slice(0,pkBytes).deep
    } else {
      pkLogic &= FastCryptographicHash(sig.slice(sigBytes,sigBytes+pkBytes)).deep == pkSeq.slice(pkBytes,2*pkBytes).deep
    }
    for (i <- 0 to pkSeq.length/pkBytes-4 by 2) {
      val pk0:Array[Byte] = pkSeq.slice((i+2)*pkBytes,(i+3)*pkBytes)
      val pk00:Array[Byte] = pkSeq.slice(i*pkBytes,(i+1)*pkBytes)
      val pk01:Array[Byte] = pkSeq.slice((i+1)*pkBytes,(i+2)*pkBytes)
      val pk1:Array[Byte] = pkSeq.slice((i+3)*pkBytes,(i+4)*pkBytes)
      val pk10:Array[Byte] = pkSeq.slice(i*pkBytes,(i+1)*pkBytes)
      val pk11:Array[Byte] = pkSeq.slice((i+1)*pkBytes,(i+2)*pkBytes)
      if((step.toInt/exp(i/2+1)) % 2 == 0) {
        pkLogic &= pk0.deep == FastCryptographicHash(pk00++pk01).deep
      } else {
        pkLogic &= pk1.deep == FastCryptographicHash(pk10++pk11).deep
      }
    }
    pkLogic &= pk.deep == FastCryptographicHash(pkSeq.slice(pkSeq.length-2*pkBytes,pkSeq.length)).deep
    sVerify(m++stepBytes,sig.slice(0,sigBytes),sig.slice(sigBytes,sigBytes+pkBytes)) && pkLogic
  }

  def sumGetKeyTimeStep(key: Tree[Array[Byte]]): Int = {
    key match {
      case n: Node[Array[Byte]] => {
        val left = n.l match {
          case n: Node[Array[Byte]] => {sumGetKeyTimeStep(n)}
          case l: Leaf[Array[Byte]] => {0}
          case _ => 0
        }
        val right = n.r match {
          case n: Node[Array[Byte]] => {sumGetKeyTimeStep(n)+exp(n.height)}
          case l: Leaf[Array[Byte]] => {1}
          case _ => 0
        }
        left+right
      }
      case l: Leaf[Array[Byte]] => 0
      case _ => 0
    }
  }

  def generateKey(seed: Array[Byte],logl:Int): MalkinKey = {
    val r = PRNG(seed)
    val rp = PRNG(r._2)
    val L = sumGenerateKey(r._1,logl)
    val Si = sumGenerateKey(rp._1,0)
    val pk1 = sumGetPublicKey(Si)
    val sig = sumSign(L,pk1,0)
    assert(sumVerify(sumGetPublicKey(L),pk1,sig))
    (L,Si,sig,pk1,rp._2)
  }

  def updateKey(key: MalkinKey,t:Int): MalkinKey = {
    val keyTime = getKeyTimeStep(key)
    var L = key._1
    var Si = key._2
    var sig = key._3
    var pk1 = key._4
    var seed = key._5
    val Tl = exp(L.height)
    var Ti = exp(Si.height)
    var tl = sumGetKeyTimeStep(L)
    var ti = sumGetKeyTimeStep(Si)
    if (keyTime < t) {
      for(i <- keyTime+1 to t) {
        tl = sumGetKeyTimeStep(L)
        ti = sumGetKeyTimeStep(Si)
        if (ti+1 < Ti) {
          Si = sumUpdate(Si, ti + 1)
        } else if (tl < Tl) {
          val r = PRNG(seed)
          Si = sumGenerateKey(r._1, tl + 1)
          pk1 = sumGetPublicKey(Si)
          seed = r._2
          Ti = exp(Si.height)
          L = sumUpdate(L, tl + 1)
          tl = sumGetKeyTimeStep(L)
          sig = sumSign(L,pk1,tl)
        } else {
          println("Error: max time steps reached")
        }
      }
    } else {
      println("Error: t less than given keyTime")
    }
    (L,Si,sig,pk1,seed)
  }


  def updateKeyFast(key: MalkinKey,t:Int): MalkinKey = {
    val keyTime = getKeyTimeStep(key)
    var L = key._1
    var Si = key._2
    var sig = key._3
    var pk1 = key._4
    var seed = key._5
    val Tl = exp(L.height)
    var Ti = exp(Si.height)
    var tl = sumGetKeyTimeStep(L)
    var ti = sumGetKeyTimeStep(Si)
    if (keyTime < t) {
      var i = keyTime+1
      while(i < t) {
        tl = sumGetKeyTimeStep(L)
        ti = sumGetKeyTimeStep(Si)
        if (t-i > exp(tl)-ti) {
          val r = PRNG(seed)
          seed = r._2
          L = sumUpdate(L, tl + 1)
          tl = sumGetKeyTimeStep(L)
          sig = sumSign(L,pk1,tl)
        } else {
          if (ti+1 < Ti) {
            Si = sumUpdate(Si, ti + 1)
          } else if (tl < Tl) {
            val r = PRNG(seed)
            Si = sumGenerateKey(r._1, tl + 1)
            pk1 = sumGetPublicKey(Si)
            seed = r._2
            Ti = exp(Si.height)
            L = sumUpdate(L, tl + 1)
            tl = sumGetKeyTimeStep(L)
            sig = sumSign(L,pk1,tl)
          } else {
            println("Error: max time steps reached")
          }
        }
        i+=1
      }
    } else {
      println("Error: t less than given keyTime")
    }
    (L,Si,sig,pk1,seed)
  }

  def getKeyTimeStep(key: MalkinKey): Int = {
    val L = key._1
    val Si = key._2
    val tl = sumGetKeyTimeStep(L)
    val ti = sumGetKeyTimeStep(Si)
    exp(tl)-1+ti
  }

  def sign(key: MalkinKey,m: Array[Byte],step:Int): MalkinSignature = {
    val keyTime = getKeyTimeStep(key)
    val L = key._1
    val Si = key._2
    val sig1 = key._3
    val pk1 = key._4
    val seed = key._5
    val ti = sumGetKeyTimeStep(Si)
    val tl = sumGetKeyTimeStep(L)
    val sig2 = sumSign(Si,m,ti)
    (sig1,sig2,pk1)
  }

  def verify(pk: Array[Byte],m: Array[Byte],sig: MalkinSignature): Boolean = {
    val sig1 = sig._1
    val sig2 = sig._2
    val pk1 = sig._3
    sumVerify(pk,pk1,sig1) && sumVerify(pk1,m,sig2)
  }

  def publicKey(key: MalkinKey):  Array[Byte] = {
    sumGetPublicKey(key._1)
  }

}
