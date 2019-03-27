package crypto

import java.io.File

import bifrost.crypto.hash.FastCryptographicHash
import bifrost.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile
import bifrost.forwardkeygen.ForwardKeyFile.uuid
import bifrost.transaction.box.proposition.{MofNProposition, ProofOfKnowledgeProposition, PublicKey25519Proposition}
import bifrost.transaction.state.PrivateKey25519
import scorex.crypto.encode.Base58
import bifrost.utils.ScorexLogging
import scorex.crypto.signatures.SigningFunctions.Signature

import scala.reflect.io.Path
import scala.util.{Failure, Success, Try}
import scorex.crypto.signatures.{Curve25519, SigningFunctions}
import sun.security.util.Password

object cryptoMain extends cryptoValues with App {

  //SIG algorithm:

  //KG - generation of PK0 and SK0
  println("Generating Key")
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  val exampleKey = KeyFile(password = password, defaultKeyDir = keyFileDir)

  //SIGN - signature generated with SK0
  println("Signing message")
  val exampleSignature = Curve25519.sign(exampleKey.getPrivateKey(password = password).get.privKeyBytes,message)

  //VER - signature verified with PK0
  println("Verify signature")
  assert(Curve25519.verify(exampleSignature,message,exampleKey.pubKeyBytes))

  //FWSIG algorithm:

  //FWKG - generation of PK0 and SK0
  println("Generating forward KeyFile")
  val FWKey = ForwardKeyFile(password,seed,keyFileDir)

  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t
  def forwardPRG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val kp = FastCryptographicHash(k)
    val r = FastCryptographicHash(kp)
    (kp,r)
  }

  //FWUPD - update PK0 and SK0 --> PK0 and SKt where t is in 0 to T
  def forwardUpdate(forwardKeyFile: ForwardKeyFile,seed: Array[Byte],password: String): ForwardKeyFile = {
    forwardKeyFile.forwardPKSK(seed,password)
    forwardKeyFile
  }
  //FWCERT - generate certificates for signing in each epoch
  def certificates(forwardKeyFile: ForwardKeyFile,password: String): List[(Array[Byte],Int,Array[Byte],Signature)] = {
    var tempList = List[(Array[Byte],Int,Array[Byte],Signature)]()
    val sk0 = forwardKeyFile.getPrivateKey(password).get.privKeyBytes
    val k0 = seed
    var kold = k0
    for (i <- 1 to T) {
      println("working on cert "+i.toString)
      val (k, r) = forwardPRG(kold)
      kold = k
      forwardKeyFile.forwardPKSK(k,password)
      val tempTuple = (forwardKeyFile.basePubKeyBytes,
        i,
        forwardKeyFile.pubKeyBytes,
        Curve25519.sign(
          sk0,
          forwardKeyFile.basePubKeyBytes++Array(i.toByte)++forwardKeyFile.pubKeyBytes
        )
      )
      tempList = tempList++List(tempTuple)
    }
    tempList
  }

  println("Generating Certificates")
  println(FWKey.getPrivateKey(password).toString)
  val certs = certificates(FWKey,password)
  println(FWKey.getPrivateKey(password).toString)
  //FWSIGN - signature generated with SKt

  //FWVER - signature verified with PK0
}

trait cryptoValues {
  val keyFileDir = "/tmp/scorex/test-data/keyfiles/crypto"
  val path: Path = Path(keyFileDir)
  val password = "password"
  val message = "message".getBytes
  val seed = FastCryptographicHash(uuid)
  val T = 10
  val t = 5
}

case class FWallet(var secrets: Set[PrivateKey25519],defaultKeyDir: String) extends ScorexLogging {
  def getListOfFiles(dir: String): List[File] = {
    val d = new File(dir)
    if (d.exists && d.isDirectory) {
      d.listFiles.filter(_.isFile).toList
    } else {
      List[File]()
    }
  }

  type S = PrivateKey25519
  type PI = ProofOfKnowledgeProposition[S]

  def publicKeys: Set[PI] = {
    //secrets.map(_.publicImage)
    getListOfFiles(defaultKeyDir).map(file => PublicKey25519Proposition(ForwardKeyFile.readFile(file.getPath).pubKeyBytes))
      .toSet
  }

  def unlockKeyFile(publicKeyString: String, password: String): Unit = {
    val keyfiles = getListOfFiles(defaultKeyDir)
      .map(file => ForwardKeyFile.readFile(file.getPath))
      .filter(k => k
        .pubKeyBytes sameElements Base58
        .decode(publicKeyString)
        .get)

    assert(keyfiles.size == 1, "Cannot find a unique publicKey in key files")
    val privKey = keyfiles.head.getPrivateKey(password) match {
      case Success(priv) => Set(priv)
      case Failure(e) => throw e
    }
    // ensure no duplicate by comparing privKey strings
    if (!secrets.map(p => Base58.encode(p.privKeyBytes)).contains(Base58.encode(privKey.head.privKeyBytes))) {
      // secrets.empty // should empty the current set of secrets meaning unlock only allows a single key to be unlocked at once
      secrets += privKey.head
    } else {
      log.warn(s"$publicKeyString is already unlocked")
    }
  }

  def lockKeyFile(publicKeyString: String, password: String): Unit = {
    val keyfiles = getListOfFiles(defaultKeyDir)
      .map(file => ForwardKeyFile.readFile(file.getPath))
      .filter(k => k
        .pubKeyBytes sameElements Base58
        .decode(publicKeyString)
        .get)
    assert(keyfiles.size == 1, "Cannot find a unique publicKey in key files")
    val privKey = keyfiles.head.getPrivateKey(password) match {
      case Success(priv) => Set(priv)
      case Failure(e) => throw e
    }
    // ensure no duplicate by comparing privKey strings
    if (!secrets.map(p => Base58.encode(p.privKeyBytes)).contains(Base58.encode(privKey.head.privKeyBytes))) {
      log.warn(s"$publicKeyString is already locked")
    } else {
      secrets -= (secrets find (p => Base58.encode(p.privKeyBytes) == Base58.encode(privKey.head.privKeyBytes))).get
    }
  }
  def generateNewSecret(password: String): PublicKey25519Proposition = {
    val privKey = KeyFile(password = password, defaultKeyDir = defaultKeyDir).getPrivateKey(password).get
    secrets += privKey
    privKey.publicImage
  }

  def generateNewSecret(password: String, importSeed: String): PublicKey25519Proposition = {
    val privKey = KeyFile(password,seed = FastCryptographicHash(importSeed), defaultKeyDir = defaultKeyDir).getPrivateKey(password).get
    secrets += privKey
    privKey.publicImage
  }

  def inWallet(publicImage: PI): Boolean = publicImage match {
    case p: PublicKey25519Proposition => publicKeys.contains(p)
    case mn: MofNProposition => publicKeys.exists(p => mn.setOfPubKeyBytes.exists(p == PublicKey25519Proposition(_)))
  }
}


