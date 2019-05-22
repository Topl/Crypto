package crypto.crypto.malkinKES

import java.security.SecureRandom

import bifrost.crypto.hash.FastCryptographicHash
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import scorex.crypto.hash.Sha512
import crypto.crypto.tree.{Tree,Node,Leaf,Empty}



object MalkinKES {

  val seedBytes = 32
  val pkBytes = Ed25519.PUBLIC_KEY_SIZE
  val skBytes = Ed25519.SECRET_KEY_SIZE
  val hashBytes = 32

  def SHA1PRNG_secureRandom(seed: Array[Byte]):SecureRandom = {
    //This algorithm uses SHA-1 as the foundation of the PRNG. It computes the SHA-1 hash over a true-random seed value
    // concatenated with a 64-bit counter which is incremented by 1 for each operation.
    // From the 160-bit SHA-1 output, only 64 bits are used.
    val rnd: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
    rnd.setSeed(seed)
    rnd
  }

  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t
  def PRNG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val r1 = FastCryptographicHash(k)
    val r2 = FastCryptographicHash(Sha512(r1++k))
    (r1,r2)
  }

  /**
    * Generate a random keypair for Ed25519
    * @return
    */
  def sKeypair: (Array[Byte],Array[Byte]) = {
    val kpg = new Ed25519KeyPairGenerator
    kpg.init(new Ed25519KeyGenerationParameters(new SecureRandom()))
    val kp = kpg.generateKeyPair
    val sk = kp.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters].getEncoded
    val pk = kp.getPublic.asInstanceOf[Ed25519PublicKeyParameters].getEncoded
    (pk,sk)
  }

  /**
    * Generate a keypair from seed for Ed25519
    * @param seed
    * @return
    */
  def sKeypair(seed: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val kpg = new Ed25519KeyPairGenerator
    kpg.init(new Ed25519KeyGenerationParameters(SHA1PRNG_secureRandom(seed)))
    val kp = kpg.generateKeyPair
    val sk = kp.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters].getEncoded
    val pk = kp.getPublic.asInstanceOf[Ed25519PublicKeyParameters].getEncoded
    (pk,sk)
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

  def sumKeyGen(seed: Array[Byte],i:Int): Tree[Array[Byte]] = {
    if (i==0){
      Leaf(seed)
    } else {
      val r = PRNG(seed)
      Node(r._2,sumKeyGen(r._1,i-1),Empty)
    }
  }

  def sumKeyGenMerkle(seed: Array[Byte],i:Int): Tree[Array[Byte]] = {
    if (i==0){
      Leaf(seed)
    } else {
      val r = PRNG(seed)
      Node(r._2,sumKeyGenMerkle(r._1,i-1),sumKeyGenMerkle(r._2,i-1))
    }
  }

  def generateKey(seed: Array[Byte],i:Int):Tree[Array[Byte]] = {
    val seedTree = sumKeyGenMerkle(seed,i)
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
    val keyTree = populateLeaf(seedTree)
    def merklePublicKeys(t: Tree[Array[Byte]]): Tree[Array[Byte]] = {
      t match {
        case n: Node[Array[Byte]] => {
          var leftVal:Array[Byte] = Array()
          var rightVal:Array[Byte] = Array()
          val left = merklePublicKeys(n.l) match {
            case nn: Node[Array[Byte]] => {
              leftVal = nn.v
              nn
            }
            case ll: Leaf[Array[Byte]] => {
              leftVal = ll.v
              ll
            }
          }
          val right = merklePublicKeys(n.r) match {
            case nn: Node[Array[Byte]] => {
              rightVal = nn.v
              nn
            }
            case ll: Leaf[Array[Byte]] => {
              rightVal = ll.v
              ll
            }
          }
          val sk0 = leftVal.slice(seedBytes,seedBytes+skBytes)
          val pk0 = leftVal.slice(seedBytes+skBytes,seedBytes+skBytes+pkBytes)
          val pk1 = rightVal.slice(seedBytes+skBytes,seedBytes+skBytes+pkBytes)
          val pk = FastCryptographicHash(pk0++pk1)
          Node(n.v++sk0++pk0++pk1++pk,
            left,right)
        }
        case l: Leaf[Array[Byte]] => {
          l
        }
        case _ => {
          Empty
        }
      }
    }
    merklePublicKeys(keyTree)
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
            case n: Node[Array[Byte]] => println("left node found");leftIsNode = true;leftVal=n.v;n
            case l: Leaf[Array[Byte]] => println("left leaf found");leftIsLeaf = true;leftVal=l.v;l
            case _ => leftIsEmpty = true; n.l
          }
          val right = n.r match {
            case n: Node[Array[Byte]] => println("right node found");rightIsNode=true;rightVal=n.v;n
            case l: Leaf[Array[Byte]] => println("right leaf found");rightIsLeaf=true;rightVal=l.v;l
            case _ => rightIsEmpty = true; n.r
          }
          val cutBranch = isRightBranch(left)
          println("cut branch:"+cutBranch.toString)
          if (rightIsEmpty && leftIsLeaf) {
            println("right is empty and left is leaf")
            val newLeaf = Leaf(n.v)
            Node(n.v,Empty,newLeaf)
          } else if (cutBranch) {
            Node(n.v,Empty,sumKeyGen(n.v,n.height-1))
          } else if (leftIsNode && rightIsEmpty) {
            Node(leftVal,loop(left),Empty)
          } else if (leftIsEmpty && rightIsNode) {
            println("left is empty and right is node")
            Node(rightVal, Empty, loop(right))
          } else if (leftIsEmpty && rightIsLeaf) {
            println("left is empty and right is leaf")
            Empty
          } else if (leftIsEmpty && rightIsEmpty) {
            println("left and right is empty")
            Empty
          } else {
            println("did nothing")
            Node(n.v,left,right)
          }
        }
        case l: Leaf[Array[Byte]] => l
        case _ => t
      }
    }
    val keyH = key.height
    val T = scala.math.pow(2,key.height).toInt
    val keyTime = sumGetKeyTimeStep(key)
    if (t<T && keyTime < t){
      var tempKey = key
      for(i <- keyTime+1 to t) {
        println(sumGetKeyTimeStep(tempKey))
        println("updating key")
        tempKey = loop(tempKey)
      }
      tempKey
    } else {
      println("Time step error, key not updated")
      println("T: "+T.toString+", key t:"+keyTime.toString+", t:"+t.toString)
      key
    }
  }

  def sumGetKeyTimeStep(key: Tree[Array[Byte]]): Int = {
    def loop(t: Tree[Array[Byte]]): Int = {
      val out = t match {
        case n: Node[Array[Byte]] => {
          val left = n.l match {
            case n: Node[Array[Byte]] => {
              val out = loop(n)
              //println("left node found: "+out.toString)
              out
            }
            case l: Leaf[Array[Byte]] => {
              val out = 0
              //println("left leaf found: "+out.toString)
              out
            }
            case _ => 0
          }
          val right = n.r match {
            case n: Node[Array[Byte]] => {
              val out =loop(n)+scala.math.pow(2,n.height).toInt
              //println("right node found: "+out.toString)
              out
            }
            case l: Leaf[Array[Byte]] => {
              val out = 1
              //println("right leaf found: "+out.toString)
              out
            }
            case _ => 0
          }
          left+right
        }
        case l: Leaf[Array[Byte]] => 0
        case _ => 0
      }
      //println("out "+out.toString)
      out
    }
    loop(key)
  }

}
