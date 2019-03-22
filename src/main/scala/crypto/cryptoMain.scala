package crypto

import bifrost.keygen.KeyFile
import scala.reflect.io.Path
import scala.util.Try

object cryptoMain extends cryptoValues with App {
  println("Generating Key")
  Try(path.deleteRecursively())
  Try(path.createDirectory())
  val exampleKey = KeyFile(password = password, defaultKeyDir = keyFileDir)
  //Try(path.deleteRecursively())
}

trait cryptoValues {
  val keyFileDir = "/tmp/scorex/test-data/keyfiles/crypto"
  val path: Path = Path(keyFileDir)
  val password = "password"
}
