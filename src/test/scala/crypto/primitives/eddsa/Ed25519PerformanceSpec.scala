package crypto.primitives.eddsa


import java.security.SecureRandom

import crypto.primitives.{Ed25519Debug, eddsa}
import org.scalatest.FunSuite
import scorex.util.encode.Base16




 class Ed25519PerformanceSpec extends FunSuite { //    @BeforeClass
   //    public static void init()
  /* def setUp(): Unit = {
     Ed25519.precompute()
   }*/

   //    @Test
   //def testEd25519Consistency(): Unit = {


   test ("Performance comparison Java vs. Scala") {

     def prnt(tag:String,input:Array[Byte]):Unit = {
       println(tag+": "+Base16.encode(input))
     }

     if (true) {
       val t0 = System.nanoTime()
       for( a <- 1 to 10000) {
         val RANDOM = new SecureRandom(Array(1L.toByte))
         val sk = new Array[Byte](Ed25519Debug.SECRET_KEY_SIZE)
         val pk = new Array[Byte](Ed25519Debug.PUBLIC_KEY_SIZE)
         val m = new Array[Byte](255)
         val sig1 = new Array[Byte](Ed25519Debug.SIGNATURE_SIZE)
         RANDOM.nextBytes(m)
         RANDOM.nextBytes(sk)
         //prnt("sk",sk)
         Ed25519Debug.generatePublicKey(sk, 0, pk, 0)
         //prnt("pk",pk)
         val mLen = RANDOM.nextInt & 255
         //prnt("m",m)
         Ed25519Debug.sign(sk, 0, m, 0, mLen, sig1, 0)
         //prnt("sig1",sig1)


         // val shouldVerify = Ed25519Debug.verify(sig1, 0, pk, 0, m, 0, mLen)
       }
       val t1 = System.nanoTime()
       val outTime = (t1 - t0)*1.0e-9
       val tString = "%6.6f".format(outTime)
       Console.err.println("Elapsed time Java code: " , tString +"s")
     }
     //println("---------------------------------------------------------")
     if (true) {
       val t0 = System.nanoTime()
       for( a <- 1 to 10000) {
         val RANDOM = new SecureRandom(Array(1L.toByte))
         val ec = new eddsa.Ed25519
         val sk = new Array[Byte](ec.SECRET_KEY_SIZE)
         val pk = new Array[Byte](ec.PUBLIC_KEY_SIZE)
         val m = new Array[Byte](255)
         val sig1 = new Array[Byte](ec.SIGNATURE_SIZE)
         RANDOM.nextBytes(m)
         RANDOM.nextBytes(sk)
         //prnt("sk",sk)
         ec.generatePublicKey(sk, 0, pk, 0)
         //prnt("pk",pk)
         val mLen = RANDOM.nextInt & 255
         //prnt("m",m)
         ec.sign(sk, 0, m, 0, mLen, sig1, 0)
         //prnt("sig1",sig1)

         //val shouldVerify = ec.verify(sig1, 0, pk, 0, m, 0, mLen)
       }
       val t1 = System.nanoTime()
       val outTime = (t1 - t0)*1.0e-9
       val tString = "%6.6f".format(outTime)
       Console.err.println("Elapsed time Scala code: " + tString +"s")
     }

   }



}