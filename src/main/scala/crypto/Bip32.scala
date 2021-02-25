package crypto


import java.io.{ByteArrayInputStream, IOException, InputStream, OutputStream}
import java.math.BigInteger
import java.nio.{ByteBuffer, ByteOrder}
import java.security.{KeyFactory, Security}

import crypto.primitives.eddsa
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.{RIPEMD160Digest, SHA1Digest, SHA256Digest, SHA512Digest}
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.{ECDomainParameters, KeyParameter}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import scodec.bits._
/**
  * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  */
object ByteVector32 {
  val Zeroes = ByteVector32(hex"0000000000000000000000000000000000000000000000000000000000000000")
  val One = ByteVector32(hex"0100000000000000000000000000000000000000000000000000000000000000")

  def fromValidHex(str: String) = ByteVector32(ByteVector.fromValidHex(str))


}
case class ByteVector32(bytes: ByteVector) {
  require(bytes.size == 32, s"size must be 32 bytes, is ${bytes.size} bytes")

  def reverse: ByteVector32 = ByteVector32(bytes.reverse)

  override def toString: String = bytes.toHex
}

object DeterministicWallet {

      Security.addProvider(new BouncyCastleProvider())
      val f = KeyFactory.getInstance("ECDSA", "BC");
      val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
      val ecDomain = new ECDomainParameters(ecSpec.getCurve, ecSpec.getG, ecSpec.getN)

      case class KeyPath(path: Seq[Long]) {
           def lastChildNumber: Long = if (path.isEmpty) 0L else path.last

           def derive(number: Long) = KeyPath(path :+ number)

           override def toString = path.map(KeyPath.childNumberToString).foldLeft("m")(_ + "/" + _)
     }

    object KeyPath {
           val Root = KeyPath(Nil)

           /**
             *
             * @param path key path. A list of integers separated by a `/`. May start with "/" or "m/". A single quote appended
             *             at the end means use the hardened version of the ley index (example: m/44'/0'/0'/0)
             * @return a KeyPath instance
             */
           def apply(path: String): KeyPath = {
                 def toNumber(value: String): Long = if (value.last == '\'') hardened(value.dropRight(1).toLong) else value.toLong

                 val path1 = path.stripPrefix("m").stripPrefix("/")
                 if (path1.isEmpty) KeyPath.Root else new KeyPath(path1.split('/').map(toNumber).toSeq)
           }

           def childNumberToString(childNumber: Long) = if (isHardened(childNumber)) (childNumber - hardenedKeyIndex).toString + "'" else childNumber.toString
     }

     //implicit def keypath2longseq(input: KeyPath): Seq[Long] = input.path

     //implicit def longseq2keypath(input: Seq[Long]): KeyPath = KeyPath(input)

     val hardenedKeyIndex = 0x80000000L

     def hardened(index: Long): Long = hardenedKeyIndex + index

     def isHardened(index: Long): Boolean = index >= hardenedKeyIndex

     case class ExtendedPrivateKey(secretkeybytes: ByteVector32, chaincode: ByteVector32, depth: Int, path: KeyPath, parent: Long) {
       /*val seed: Array[Byte] = secretkeybytes.bytes.toArray
       val secureRandomSeed : SecureRandom = new SecureRandom(seed)

       val ec = new eddsa.Ed25519
       def sk = new Array[Byte](ec.SECRET_KEY_SIZE)
       def pk = new Array[Byte](ec.PUBLIC_KEY_SIZE)
       val m = new Array[Byte](255)
       val sig1 = new Array[Byte](ec.SIGNATURE_SIZE)
       val sig2 = new Array[Byte](ec.SIGNATURE_SIZE)
       //def privateKey: Array[Byte] = ec.generatePrivateKey(secureRandomSeed,sk)
       secureRandomSeed.nextBytes(sk)
       ec.generatePublicKey(sk, 0, pk, 0)*/

       def sk = secretkeybytes.bytes.toArray

       //get public key from private key
       val ec = new eddsa.Ed25519
       def pk = new Array[Byte](ec.PUBLIC_KEY_SIZE)
       ec.generatePublicKey(sk, 0, pk, 0)

     }
      def bytes(input: InputStream, size: Long): ByteVector = bytes(input, size.toInt)

      def bytes(input: InputStream, size: Int): ByteVector = {
        val blob = new Array[Byte](size)
        if (size > 0) {
          val count = input.read(blob)
          if (count < size) throw new IOException("not enough data to read from")
        }
        ByteVector.view(blob)
      }

     def uint8(input: InputStream): Int = input.read()

      def uint32(input: InputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Long = {
        val bin = new Array[Byte](4)
        input.read(bin)
        uint32(bin, order)
      }

      def uint32(input: Array[Byte], order: ByteOrder): Long = {
        val buffer = ByteBuffer.wrap(input).order(order)
        buffer.getInt() & 0xFFFFFFFFL
      }

      def uint32(input: ByteVector, order: ByteOrder): Long = {
        input.toLong(signed = false, ByteOrdering.fromJava(order))
      }
     object ExtendedPrivateKey {
           def decode(input: String, parentPath: KeyPath = KeyPath.Root): (ExtendedPrivateKey) = {
                 /*val (prefix, bin) = Base58Check.decodeWithIntPrefix(input)
                 val bis = new ByteArrayInputStream(bin.toArray)
                 val depth = Protocol.uint8(bis)
                 val parent = Protocol.uint32(bis, ByteOrder.BIG_ENDIAN)
                 val childNumber = Protocol.uint32(bis, ByteOrder.BIG_ENDIAN)
                 val chaincode = ByteVector32(Protocol.bytes(bis, 32))
                 require(bis.read() == 0)
                 val secretkeybytes = ByteVector32(Protocol.bytes(bis, 32))
                 (prefix, ExtendedPrivateKey(secretkeybytes, chaincode, depth, parentPath.derive(childNumber), parent))*/


                 val bis = new ByteArrayInputStream(input.getBytes)
                 val depth = uint8(bis)
                 val parent = uint32(bis, ByteOrder.BIG_ENDIAN)
                 val childNumber = uint32(bis, ByteOrder.BIG_ENDIAN)
                 val chaincode = ByteVector32(bytes(bis, 32))
                 require(bis.read() == 0)
                 val secretkeybytes = ByteVector32(bytes(bis, 32))
                 (ExtendedPrivateKey(secretkeybytes, chaincode, depth, parentPath.derive(childNumber), parent))
           }
     }

     /*def encode(input: ExtendedPrivateKey, prefix: Int): String = {
           val out = new ByteArrayOutputStream()
           writeUInt8(input.depth, out)
           writeUInt32(input.parent.toInt, out, ByteOrder.BIG_ENDIAN)
           writeUInt32(input.path.lastChildNumber.toInt, out, ByteOrder.BIG_ENDIAN)
           out.write(input.chaincode.toArray)
           out.write(0)
           out.write(input.secretkeybytes.toArray)
           val buffer = ByteVector.view(out.toByteArray)
           Base58Check.encode(prefix, buffer)
     }*/

      case class ExtendedPublicKey(publickeybytes: ByteVector, chaincode: ByteVector32, depth: Int, path: KeyPath, parent: Long) {
        require(publickeybytes.length == 33)
        require(chaincode.bytes.length == 32)

        def pk  = publickeybytes.toArray


      }

      object ExtendedPublicKey {
        def decode(input: String, parentPath: KeyPath = KeyPath.Root): (ExtendedPublicKey) = {
         // val (prefix, bin) = Base58Check.decodeWithIntPrefix(input)
          val bis = new ByteArrayInputStream(input.getBytes)
          val depth = uint8(bis)
          val parent = uint32(bis, ByteOrder.BIG_ENDIAN)
          val childNumber = uint32(bis, ByteOrder.BIG_ENDIAN)
          val chaincode = ByteVector32(bytes(bis, 32))
          val publickeybytes = bytes(bis, 33)
          (ExtendedPublicKey(publickeybytes, chaincode, depth, parentPath.derive(childNumber), parent))
        }
      }

     /*def encode(input: ExtendedPublicKey, prefix: Int): String = {
           val out = new ByteArrayOutputStream()
           write(input, out)
           val buffer = ByteVector.view(out.toByteArray)
           Base58Check.encode(prefix, buffer)
     }*/

     /*def write(input: ExtendedPublicKey, output: OutputStream): Unit = {
           writeUInt8(input.depth, output)
           writeUInt32(input.parent.toInt, output, ByteOrder.BIG_ENDIAN)
           writeUInt32(input.path.lastChildNumber.toInt, output, ByteOrder.BIG_ENDIAN)
           writeBytes(input.chaincode.toArray, output)
           writeBytes(input.publickeybytes.toArray, output)
     }*/

    def hmac512(key: ByteVector, data: ByteVector): ByteVector = {
      val mac = new HMac(new SHA512Digest())
      mac.init(new KeyParameter(key.toArray))
      mac.update(data.toArray, 0, data.length.toInt)
      val out = new Array[Byte](64)
      mac.doFinal(out, 0)
      ByteVector.view(out)
    }
     /**
       *
       * @param seed random seed
       * @return a "master" private key
       */
     def generate(seed: ByteVector): ExtendedPrivateKey = {
           val I = hmac512(ByteVector.view("Bitcoin seed".getBytes("UTF-8")), seed)
           val IL = ByteVector32(I.take(32))
           val IR = ByteVector32(I.takeRight(32))
           val path: KeyPath = new KeyPath(List.empty[Long])
           ExtendedPrivateKey(IL, IR, depth = 0, path, parent = 0L)
     }

     /**
       *
       * @param input extended private key
       * @return the public key for this private key
       */
     def publicKey(input: ExtendedPrivateKey): ExtendedPublicKey = {
           ExtendedPublicKey(ByteVector(input.pk), input.chaincode, depth = input.depth, path = input.path, parent = input.parent)
     }


    def hash(digest: Digest)(input: ByteVector): ByteVector = {
      digest.update(input.toArray, 0, input.length.toInt)
      val out = new Array[Byte](digest.getDigestSize)
      digest.doFinal(out, 0)
      ByteVector.view(out)
    }

    def sha1 = hash(new SHA1Digest) _
    def sha256 = (x: ByteVector) => ByteVector32(hash(new SHA256Digest)(x))

    def ripemd160 = hash(new RIPEMD160Digest) _
    def hash160(input: ByteVector): ByteVector = ripemd160(sha256(input).bytes)
     /**
       *
       * @param input extended public key
       * @return the fingerprint for this public key
       */
     def fingerprint(input: ExtendedPublicKey): Long = uint32(new ByteArrayInputStream(hash160(ByteVector(input.pk)).take(4).reverse.toArray))

     /**
       *
       * @param input extended private key
       * @return the fingerprint for this private key (which is based on the corresponding public key)
       */
      def fingerprint(input: ExtendedPrivateKey): Long = fingerprint(publicKey(input))


      def writeUInt32(input: Long, out: OutputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Unit = out.write(writeUInt32(input, order).toArray)

      def writeUInt32(input: Long, order: ByteOrder): ByteVector = {
        val bin = new Array[Byte](4)
        val buffer = ByteBuffer.wrap(bin).order(order)
        buffer.putInt((input & 0xffffffff).toInt)
        ByteVector.view(bin)
      }

      def writeUInt32(input: Long): ByteVector = writeUInt32(input, ByteOrder.LITTLE_ENDIAN)

     /**
       *
       * @param parent extended private key
       * @param index  index of the child key
       * @return the derived private key at the specified index
       */
     def derivePrivateKey(parent: ExtendedPrivateKey, index: Long): ExtendedPrivateKey = {
           val I = if (isHardened(index)) {
                 val buffer =  parent.secretkeybytes.bytes.+:(0.toByte)
                 hmac512(parent.chaincode.bytes, buffer ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
           } else {
             val pub = publicKey(parent).publickeybytes
                 hmac512(parent.chaincode.bytes, pub ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
           }
           val IL = ByteVector32(I.take(32))
           val IR = ByteVector32(I.takeRight(32))

           val bigIntKey = BigInt( IL.bytes.toArray)
           val bigIntParKey = BigInt(parent.sk.toArray)
           val N = Math.pow(2,252) + BigDecimal("27742317777372353535851937790883648493")


           if (bigIntKey.compareTo(N.toBigInt())>= 0) {
                 throw new RuntimeException("cannot generated child private key")
           }


           //val key = ( bigIntKey + bigIntParKey).mod(N.toBigInt())



           val li = (bigIntKey + bigIntParKey).mod(ecSpec.getN())
           val key = f.generatePrivate(new ECPrivateKeySpec(li.bigInteger, ecSpec)).asInstanceOf[ECPrivateKey]

           if (li == 0) {
             throw new RuntimeException("cannot generated child private key")
           }
           val buffer = ByteVector32(ByteVector(key.getEncoded))
           ExtendedPrivateKey(buffer, chaincode = IR, depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
     }

     /**
       *
       * @param parent extended public key
       * @param index  index of the child key
       * @return the derived public key at the specified index
       */
     def derivePublicKey(parent: ExtendedPublicKey, index: Long): ExtendedPublicKey = {
           require(!isHardened(index), "Cannot derive public keys from public hardened keys")

           val I = hmac512(parent.chaincode.bytes, parent.publickeybytes ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
           val IL = ByteVector32(I.take(32))
           val IR = ByteVector32(I.takeRight(32))

           val bigIntPubKey = new BigInteger(1,IL.bytes.toArray)
           val bigIntParPubKey = new BigInteger(1, parent.pk.toArray)
           val N = Math.pow(2,252) + BigDecimal("27742317777372353535851937790883648493")


           if (bigIntPubKey.compareTo(N.toBigInt())>= 0) {
             throw new RuntimeException("cannot generated child private key")
           }

           val pubParKeyP = ecSpec.getG().multiply(bigIntParPubKey)
           val pubKey = ecSpec.getG().multiply(bigIntPubKey).add(pubParKeyP).normalize()

           if (pubKey.isInfinity) {
                 throw new RuntimeException("cannot generated child public key")
           }
           val buffer = ByteVector(pubKey.getEncoded(false))
           ExtendedPublicKey(buffer, chaincode = IR, depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
     }

     //def derivePrivateKey(parent: ExtendedPrivateKey, chain: Seq[Long]): ExtendedPrivateKey = chain.foldLeft(parent)(derivePrivateKey)

     //def derivePrivateKey(parent: ExtendedPrivateKey, keyPath: KeyPath): ExtendedPrivateKey = derivePrivateKey(parent, keyPath.path)

     //def derivePublicKey(parent: ExtendedPublicKey, chain: Seq[Long]): ExtendedPublicKey = chain.foldLeft(parent)(derivePublicKey)

     //def derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey = derivePublicKey(parent, keyPath.path)



     // p2pkh mainnet
     val xprv = 0x0488ade4
     val xpub = 0x0488b21e

     // p2sh-of-p2wpkh mainnet
     val yprv = 0x049d7878
     val ypub = 0x049d7cb2

     // p2wpkh mainnet
     val zprv = 0x04b2430c
     val zpub = 0x04b24746

     // p2pkh testnet
     val tprv = 0x04358394
     val tpub = 0x043587cf

     // p2sh-of-p2wpkh testnet
     val uprv = 0x044a4e28
     val upub = 0x044a5262

     // p2wpkh testnet
     val vprv = 0x045f18bc
     val vpub = 0x045f1cf6
}

