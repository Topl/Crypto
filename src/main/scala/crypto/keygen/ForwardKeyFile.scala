package crypto.forwardkeygen

import java.io.{BufferedWriter, FileWriter}
import java.lang.reflect.Constructor
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.temporal.ChronoUnit

import crypto.forwardkeygen.ForwardKeyFile._
import io.circe.parser.parse
import io.circe.syntax._
import io.circe.{Decoder, HCursor, Json}
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.whispersystems.curve25519.OpportunisticCurve25519Provider
import bifrost.crypto.hash.FastCryptographicHash
import bifrost.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.Keccak256
import scorex.crypto.signatures.SigningFunctions.Signature
import scorex.crypto.signatures.Curve25519
import crypto.forwardtypes.forwardTypes._


import scala.util.Try

/**
  * Created by cykoz on 6/22/2017.
  */

case class ForwardKeyFile(var pubKeyBytes: Array[Byte],
                          var cipherText: Array[Byte],
                          var mac: Array[Byte],
                          salt: Array[Byte],
                          iv: Array[Byte],
                          basePubKeyBytes: Array[Byte],
                          var epochNum: Int,
                          var certificates: List[Cert]
                         ) {
  var fileName: String = ""
  var json: Json = "".asJson

  def updateJson: Unit = {
    json = Map(
      "publicKeyId" -> Base58.encode(basePubKeyBytes).asJson,
      "evolvedPublicKey" -> Base58.encode(pubKeyBytes).asJson,
      "epochNumber" -> epochNum.toString.asJson,
      "crypto" -> Map(
        "cipher" -> "aes-128-ctr".asJson,
        "cipherParams" -> Map(
          "iv" -> Base58.encode(iv).asJson
        ).asJson,
        "cipherText" -> Base58.encode(cipherText).asJson,
        "kdf" -> "scrypt".asJson,
        "kdfSalt" -> Base58.encode(salt).asJson,
        "mac" -> Base58.encode(mac).asJson
      ).asJson,
      "certificates" -> (certificates map {
        case (e1: Array[Byte],e2: Int, e3: Array[Byte], e4: Signature)
        => e2.toString+", "+Base58.encode(e3)+", "+Base58.encode(e4)
      }).asJson
    ).asJson
  }

  def getPrivateKey(password: String): Try[PrivateKey25519] = Try {
    val derivedKey = getDerivedKey(password, salt)
    //require(Keccak256(derivedKey.slice(16, 32) ++ cipherText) sameElements mac, "MAC does not match. Try again")
    val (decrypted, _) = getAESResult(derivedKey, iv, cipherText, encrypt = false)
    //require(pubKeyBytes sameElements getPkFromSk(decrypted.slice(0,Curve25519.KeyLength)), "PublicKey in file is invalid")
    PrivateKey25519(decrypted.slice(0,Curve25519.KeyLength), pubKeyBytes)
  }

  def getKt(password: String): Try[Array[Byte]] = Try {
    val derivedKey = getDerivedKey(password, salt)
    //require(Keccak256(derivedKey.slice(16, 32) ++ cipherText) sameElements mac, "MAC does not match. Try again")
    val (decrypted, _) = getAESResult(derivedKey, iv, cipherText, encrypt = false)
    //require(pubKeyBytes sameElements getPkFromSk(decrypted.slice(0,Curve25519.KeyLength)), "PublicKey in file is invalid")
    decrypted.drop(Curve25519.KeyLength)
  }

  def updateKeys(k: Array[Byte], r: Array[Byte],password: String): Unit = {
    val (sk, pk) = PrivateKey25519Companion.generateKeys(r)
    val derivedKey = getDerivedKey(password, salt)
    val (ct,m) = getAESResult(derivedKey, iv, sk.privKeyBytes++k, encrypt = true)
    epochNum += 1
    pubKeyBytes = pk.pubKeyBytes
    cipherText = ct
    mac = m
  }

  def saveForwardKeyFile: Unit = {
    val w = new BufferedWriter(new FileWriter(fileName))
    w.write(json.toString())
    w.close()
  }

  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t
  def forwardPRG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val kp = FastCryptographicHash(k)
    val r = FastCryptographicHash(kp)
    (kp,r)
  }

  //FWCERT - generate certificates for signing in each epoch
  def forwardCertificates(forwardKey: ForwardKeyFile, seed: Array[Byte], tMax: Int, password: String): List[Cert] = {
    var tempList = List[Cert]()
    val SK0: Array[Byte] = forwardKey.getPrivateKey(password).get.privKeyBytes
    val PK0: Array[Byte] = forwardKey.basePubKeyBytes
    val K0: Array[Byte] = seed
    var K_old: Array[Byte] = K0
    println("  Generating Certificates")
    for (i <- 0 to tMax) {
      if (i > 0) {
        val (k: Array[Byte], r: Array[Byte]) = forwardPRG(K_old)
        K_old = k
        val (_, pk) = PrivateKey25519Companion.generateKeys(r)
        forwardKey.pubKeyBytes = pk.pubKeyBytes
      }
      val PKt = forwardKey.pubKeyBytes
      val tempCert: Cert = (
        PK0,
        i,
        PKt,
        Curve25519.sign(SK0, PK0++Array(i.toByte)++PKt)
      )
      tempList = tempList++List(tempCert)
    }
    forwardKey.updateKeys(seed,seed,password)
    forwardKey.epochNum = 0
    tempList
  }

  //FWUPD - update PK0 and SK0 --> PK0 and SKt where t is in 0 to T
  def forwardUpdate(password: String): Unit = {
    val kt: Array[Byte] = getKt(password).get
    val (kp,r) = forwardPRG(kt)
    updateKeys(kp,r,password)
    updateJson
    val PKt = pubKeyBytes
    val certificate: Cert = certificates(epochNum)
    assert(basePubKeyBytes.deep == certificate._1.deep)
    assert(epochNum == certificate._2)
    assert(pubKeyBytes.deep == certificate._3.deep)
    assert(PKt.deep == PrivateKey25519Companion.generateKeys(r)._2.pubKeyBytes.deep)
  }
}

object ForwardKeyFile {

  def getDerivedKey(password: String, salt: Array[Byte]): Array[Byte] = {
    SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, scala.math.pow(2, 18).toInt, 8, 1, 32)
  }

  def getAESResult(derivedKey: Array[Byte], ivData: Array[Byte], inputText: Array[Byte], encrypt: Boolean):
  (Array[Byte], Array[Byte]) = {
    val cipherParams = new ParametersWithIV(new KeyParameter(derivedKey), ivData)
    var aesCtr = new BufferedBlockCipher(new SICBlockCipher(new AESEngine))
    aesCtr.init(encrypt, cipherParams)
    val outputText = Array.fill(inputText.length)(1: Byte)
    aesCtr.processBytes(inputText, 0, inputText.length, outputText, 0)
    aesCtr.doFinal(outputText, 0)
    (outputText, Keccak256(derivedKey.slice(16, 32) ++ outputText))
  }

  def uuid: String = java.util.UUID.randomUUID.toString

  def apply(password: String, seed: Array[Byte] = FastCryptographicHash(uuid), tMax: Int, defaultKeyDir: String): ForwardKeyFile = {
    val salt = FastCryptographicHash(uuid)
    var (sk, pk) = PrivateKey25519Companion.generateKeys(seed)
    val ivData = FastCryptographicHash(uuid).slice(0, 16)
    val derivedKey = getDerivedKey(password, salt)
    val (cipherText, mac) = getAESResult(derivedKey, ivData, sk.privKeyBytes++seed, encrypt = true)
    val tempFile = ForwardKeyFile(pk.pubKeyBytes, cipherText, mac, salt, ivData, pk.pubKeyBytes,0 , List[Cert]())
    tempFile.certificates = tempFile.forwardCertificates(tempFile,seed,tMax,password)
    val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")
    tempFile.fileName = s"$defaultKeyDir/$dateString-${Base58.encode(pk.pubKeyBytes)}.json"
    val w = new BufferedWriter(new FileWriter(s"$defaultKeyDir/$dateString-${Base58.encode(pk.pubKeyBytes)}.json"))
    tempFile.updateJson
    w.write(tempFile.json.toString())
    w.close()
    tempFile
  }

  def getPkFromSk(sk: Array[Byte]): Array[Byte] = provider.generatePublicKey(sk)

  def readFile(filename: String): ForwardKeyFile = {
    val jsonString = scala.io.Source.fromFile(filename).mkString
    val tempF: ForwardKeyFile = parse(jsonString).right.get.as[ForwardKeyFile] match {
      case Right(f: ForwardKeyFile) => f
      case Left(e) => throw new Exception(s"Could not parse KeyFile: $e")
    }
    tempF.fileName = filename
    tempF.updateJson
    tempF
  }

  implicit val decodeKeyFile: Decoder[ForwardKeyFile] = (c: HCursor) => for {
    pubKeyString <- c.downField("publicKeyId").as[String]
    cipherTextString <- c.downField("crypto").downField("cipherText").as[String]
    macString <- c.downField("crypto").downField("mac").as[String]
    saltString <- c.downField("crypto").downField("kdfSalt").as[String]
    ivString <- c.downField("crypto").downField("cipherParams").downField("iv").as[String]
  } yield {
    val pubKey = Base58.decode(pubKeyString).get
    val cipherText = Base58.decode(cipherTextString).get
    val mac = Base58.decode(macString).get
    val salt = Base58.decode(saltString).get
    val iv = Base58.decode(ivString).get
    ForwardKeyFile(pubKey, cipherText, mac, salt, iv, pubKey, 0, List[Cert]())
  }

  private val provider: OpportunisticCurve25519Provider = {
    val constructor = classOf[OpportunisticCurve25519Provider]
      .getDeclaredConstructors
      .head
      .asInstanceOf[Constructor[OpportunisticCurve25519Provider]]
    constructor.setAccessible(true)
    constructor.newInstance()
  }
}
