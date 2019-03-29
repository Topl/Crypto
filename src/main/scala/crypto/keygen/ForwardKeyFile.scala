package bifrost.forwardkeygen

import java.io.{BufferedWriter, FileWriter}
import java.lang.reflect.Constructor
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.temporal.ChronoUnit

import bifrost.forwardkeygen.ForwardKeyFile._
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

import scala.util.Try

/**
  * Created by cykoz on 6/22/2017.
  */

case class ForwardKeyFile(var pubKeyBytes: Array[Byte],
                          var cipherText: Array[Byte],
                          var mac: Array[Byte],
                          salt: Array[Byte],
                          iv: Array[Byte],
                          basePubKeyBytes: Array[Byte]) {

  def getPrivateKey(password: String): Try[PrivateKey25519] = Try {
    val derivedKey = getDerivedKey(password, salt)
    require(Keccak256(derivedKey.slice(16, 32) ++ cipherText) sameElements mac, "MAC does not match. Try again")

    val (decrypted, _) = getAESResult(derivedKey, iv, cipherText, encrypt = false)
    require(pubKeyBytes sameElements getPkFromSk(decrypted), "PublicKey in file is invalid")

    PrivateKey25519(decrypted, pubKeyBytes)
  }

  def forwardPKSK(seed: Array[Byte],password: String): Unit = {
    val (sk, pk) = PrivateKey25519Companion.generateKeys(seed)
    val derivedKey = getDerivedKey(password, salt)
    val (ct,m) = getAESResult(derivedKey, iv, sk.privKeyBytes, encrypt = true)
    pubKeyBytes = pk.pubKeyBytes
    cipherText = ct
    mac = m
    json = Map(
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
      "publicKeyId" -> Base58.encode(pubKeyBytes).asJson,
      "certificates" -> certificates.asJson
    ).asJson
    val w = new BufferedWriter(new FileWriter(fileName))
    w.write(json.toString())
    w.close()
  }

  var certificates = List[(Array[Byte],Int,Array[Byte],Signature)]()

  var fileName: String = ""

  var json: Json = Map(
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
    "publicKeyId" -> Base58.encode(pubKeyBytes).asJson,
    "certificates" -> certificates.asJson
  ).asJson
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

    val outputText = Array.fill(32)(1: Byte)
    aesCtr.processBytes(inputText, 0, inputText.length, outputText, 0)
    aesCtr.doFinal(outputText, 0)

    (outputText, Keccak256(derivedKey.slice(16, 32) ++ outputText))
  }

  def uuid: String = java.util.UUID.randomUUID.toString

  def apply(password: String, seed: Array[Byte] = FastCryptographicHash(uuid), defaultKeyDir: String): ForwardKeyFile = {

    val salt = FastCryptographicHash(uuid)

    var (sk, pk) = PrivateKey25519Companion.generateKeys(seed)

    val ivData = FastCryptographicHash(uuid).slice(0, 16)

    val derivedKey = getDerivedKey(password, salt)
    val (cipherText, mac) = getAESResult(derivedKey, ivData, sk.privKeyBytes, encrypt = true)

    val tempFile = ForwardKeyFile(pk.pubKeyBytes, cipherText, mac, salt, ivData, pk.pubKeyBytes)

    val dateString = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString.replace(":", "-")
    tempFile.fileName = s"$defaultKeyDir/$dateString-${Base58.encode(pk.pubKeyBytes)}.json"
    val w = new BufferedWriter(new FileWriter(s"$defaultKeyDir/$dateString-${Base58.encode(pk.pubKeyBytes)}.json"))
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
    ForwardKeyFile(pubKey, cipherText, mac, salt, iv, pubKey)
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
