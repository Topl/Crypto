package crypto.ouroboros

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

object sharedData extends obTypes {
  var counter = 0
  var errorFlag = false
  var killFlag = false
  var txCounter = 0
  var printingHolder = 0
  var setOfTxs:Map[Sid,Int] = Map()
  def count:Int = {
    val out = counter
    counter += 1
    println(counter)
    out
  }
  def throwError = {errorFlag=true}
  def error:Boolean = {errorFlag}
}

trait utils {

  def uuid: String = java.util.UUID.randomUUID.toString

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

}
