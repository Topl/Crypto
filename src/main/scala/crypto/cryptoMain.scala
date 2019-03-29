package crypto

import java.io.File

import bifrost.crypto.hash.FastCryptographicHash
import bifrost.forwardkeygen.ForwardKeyFile
import bifrost.keygen.KeyFile
import bifrost.forwardkeygen.ForwardKeyFile.uuid
import bifrost.transaction.box.proposition.{MofNProposition, ProofOfKnowledgeProposition, PublicKey25519Proposition}
import bifrost.transaction.state.{PrivateKey25519, PrivateKey25519Companion}
import scorex.crypto.encode.Base58
import bifrost.utils.ScorexLogging
import scorex.crypto.signatures.SigningFunctions.Signature

import scala.reflect.io.Path
import scala.util.{Failure, Success, Try}
import scorex.crypto.signatures.{Curve25519, SigningFunctions}
import sun.security.util.Password

object cryptoMain extends cryptoValues with App {

  //SIG algorithm:
  println("\nOld Signing Algorithm:")
  //KG - generation of PK0 and SK0
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  println("  Generating Key...")
  val exampleKey = KeyFile(password = password, defaultKeyDir = keyFileDir)

  //SIGN - signature generated with SK0
  println("  Signing message...")
  val exampleSignature = Curve25519.sign(exampleKey.getPrivateKey(password = password).get.privKeyBytes,message)

  //VER - signature verified with PK0
  println("  Verify signature...")
  assert(Curve25519.verify(exampleSignature,message,exampleKey.pubKeyBytes))


  println("\nForward Signing Algorithm:")

  //FWSIG algorithm:
  type Cert = (Array[Byte],Int,Array[Byte],Signature)
  type ForwardSig = (Cert,Signature,Int)

  //FWPRG - pseudorandom generator
  // input: number k_(t-1)
  // output: pair of pseudorandom numbers k_t , r_t
  def forwardPRG(k: Array[Byte]): (Array[Byte],Array[Byte]) = {
    val kp = FastCryptographicHash(k)
    val r = FastCryptographicHash(kp)
    (kp,r)
  }

  //FWUPD - update PK0 and SK0 --> PK0 and SKt where t is in 0 to T
  def forwardUpdate(forwardKeyFile: ForwardKeyFile,k: Array[Byte],password: String,t: Int): Array[Byte] = {
    val (kp,r) = forwardPRG(k)
    forwardKeyFile.forwardPKSK(r,password)
    val pkt = forwardKeyFile.pubKeyBytes
    val certificate: Cert = forwardKeyFile.certificates(t)
    assert(forwardKeyFile.basePubKeyBytes.deep == certificate._1.deep)
    assert(t == certificate._2)
    assert(forwardKeyFile.pubKeyBytes.deep == certificate._3.deep)
    assert(pkt.deep == PrivateKey25519Companion.generateKeys(r)._2.pubKeyBytes.deep)
    kp
  }

  def binaryArrayToHex(b: Array[Byte]): String = {
    b.map("%02x" format _).mkString
  }

  //FWCERT - generate certificates for signing in each epoch
  def forwardCertificates(forwardKeyFile: ForwardKeyFile,password: String): List[(Array[Byte],Int,Array[Byte],Signature)] = {
    var tempList = List[Cert]()
    val sk0 = forwardKeyFile.getPrivateKey(password).get.privKeyBytes
    val pk0 = forwardKeyFile.pubKeyBytes
    val k0 = seed
    var kOld = k0
    for (i <- 0 to T) {
      println("    Working on cert "+i.toString)
      if (i > 0) {
        val (k, r) = forwardPRG(kOld)
        kOld = k
        forwardKeyFile.forwardPKSK(r,password)
      }
      val tempCert: Cert = (pk0,
        i,
        forwardKeyFile.pubKeyBytes,
        Curve25519.sign(
          sk0,
          forwardKeyFile.basePubKeyBytes++Array(i.toByte)++forwardKeyFile.pubKeyBytes
        )
      )
      tempList = tempList++List(tempCert)
    }
    forwardKeyFile.forwardPKSK(seed,password)
    tempList
  }

  //FWVER - signature verified with PK0
  def forwardVerify(pk0: Array[Byte],m: Array[Byte],s: ForwardSig): Boolean = {
    val c: Cert = s._1
    val sig: Signature = s._2
    val t: Int = s._3
    val pk0_c = c._1
    val t_c = c._2
    val pkt: Array[Byte] = c._3
    val sig_c: Signature = c._4
    assert(pk0.deep == pk0_c.deep)
    assert(t == t_c)
    assert(Curve25519.verify(sig_c,pk0++Array(t.toByte)++pkt,pk0))
    Curve25519.verify(sig,m,pkt)
  }

  //FWSIGN - signature generated with SKt
  def increment(n:Int): Unit = {
    t0 = t
    tp = t+n-1
    for (i <- t0 to tp) {
      t = i+1
      println("    t = "+t.toString)
      kt = forwardUpdate(FWKey,kt,password,t)
    }
  }

  def forwardSignature(fwk: ForwardKeyFile, password: String, message: Array[Byte] , t: Int): ForwardSig = {
    (fwk.certificates(t), Curve25519.sign(fwk.getPrivateKey(password).get.privKeyBytes,message), t)
  }

  //FWKG - generation of PK0 and SK0
  println("  Generating Forward KeyFile")
  val FWKey: ForwardKeyFile = ForwardKeyFile(password,seed,keyFileDir)

  println("  Signing Message with SK0")
  val exampleForwardSignature0: Signature = Curve25519.sign(FWKey.getPrivateKey(password).get.privKeyBytes,message)

  println("  Generating Certificates")
  FWKey.certificates = forwardCertificates(FWKey,password)

  println("  Verify Signature made with SK0, indicating FWKey is at state 0")
  assert(Curve25519.verify(exampleForwardSignature0,message,FWKey.pubKeyBytes))

  println("  Evolving Key...")
  increment(inc1)

  println("  Making Forward Signature 1")
  val forwardSignature1: ForwardSig = forwardSignature(FWKey,password,message,t)

  println("  Evolving Key...")
  increment(inc2)

  println("  Making Forward Signature 2")
  val forwardSignature2: ForwardSig = forwardSignature(FWKey,password,message,t)

  println("  Evolving Key...")
  increment(inc3)

  println("  Verify Signature made with SK0 with evolved PKt (should fail)")
  println("    "+Try(Curve25519.verify(exampleForwardSignature0,message,FWKey.pubKeyBytes)))

  println("  Verify Signature made with SK0 with base pubKey (should succeed)")
  println("    "+Try(Curve25519.verify(exampleForwardSignature0,message,FWKey.basePubKeyBytes)))

  println("  Attempting to forge false signature...")
  val forwardSignature3: ForwardSig =
    (
      FWKey.certificates(5),
      Curve25519.sign(FWKey.getPrivateKey(password).get.privKeyBytes,message),
      5
    )

  println("  Verifying Forward Signature 1")
  assert(forwardVerify(FWKey.basePubKeyBytes,message,forwardSignature1))

  println("  Verifying Forward Signature 2")
  assert(forwardVerify(FWKey.basePubKeyBytes,message,forwardSignature2))

  println("  Verify false Signature 3 (should fail)")
  println("    "+Try(forwardVerify(FWKey.basePubKeyBytes,message,forwardSignature3)))

}

trait cryptoValues {
  val keyFileDir = "/tmp/scorex/test-data/keyfiles/crypto"
  val path: Path = Path(keyFileDir)
  val password = "password"
  val message = "message".getBytes
  val seed = FastCryptographicHash(uuid)
  val T = 12
  val inc1 = 3
  val inc2 = 2
  val inc3 = 5
  var t: Int = 0
  var t0: Int = 0
  var tp: Int = 0
  var kt: Array[Byte] = seed
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


