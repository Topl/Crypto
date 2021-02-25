package csgSim

import com.google.common.primitives.Ints
import com.google.common.primitives.Bytes

import scala.collection.mutable
import scala.math
import scala.util.Random

class CsgSimulation {

  println("Conditional Settlement Game Simulation")

  val numHolders = 100
  val T = 1000
  val rnd:Random = new Random(0L)

  val gamma = 40
  val psi = 0

  val f_A = 0.4
  val f_B = 0.1

  //testing is assumed to follow VRF ideal functionality
  def y_test(sl:Int,id:Int):Double = {
    val r:Random = new Random(BigInt(Ints.toByteArray(sl)++Ints.toByteArray(id)).toLong)
    r.nextDouble()
  }

  //difficulty curve
  def f(d:Int):Double = {
    d match {
      case _ if d>gamma => f_B
      case _ if d<psi => 0.0
      case _ => f_A*(d-psi)/(gamma-psi).toDouble
    }
  }

  //threshold phi(delta,alpha)
  def phi(d:Int,a:Double): Double = {
    math.pow(1-f(d),a)
  }

  //blocks only contain enough information to construct tines
  case class Block(sl:Int,psl:Int,n:Int,id:Int,pid:Int)

  val blockDb:mutable.Map[Int,Block] = mutable.Map(0 -> Block(0,0,0,0,0))

  val stakeDist:mutable.Map[Int,Double]= {
    val out:mutable.Map[Int,Double] = mutable.Map.empty
    for (i <- 1 to numHolders) {
      out.update(i,1.0/numHolders)
    }
    out
  }

  trait Holder {
    val id:Int
    val alpha:Double
  }

  case class Honest(var head:Int, override val id:Int, override val alpha: Double) extends Holder {
    def chainSelect(b:Block):Unit = if (b.n > blockDb(head).n) head = b.id
    def test(sl:Int):Option[Block] = {
      val pb = blockDb(head)
      if (y_test(sl,id) < phi(sl-pb.sl,alpha)) {
        Some(Block(sl,pb.sl,pb.n+1,rnd.nextInt(),pb.id))
      } else {
        None
      }
    }
  }

  case class Adversarial(override val id:Int, override val alpha: Double) extends Holder

}
