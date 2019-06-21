package crypto.ouroboros

import crypto.crypto.malkinKES.MalkinKES.MalkinSignature
import scala.math.BigInt

trait obTypes {
  type Eta = Array[Byte]
  type Sig = Array[Byte]
  type Slot = Int
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
  type Sid = Array[Byte]
  type PublicKeys = (PublicKey,PublicKey,PublicKey)
  type Party = List[PublicKeys]
  type PrivateKey = Array[Byte]
  type Hash = Array[Byte]
  type Pi = Array[Byte]
  type Tx = (Array[Byte],Sid,Sig,PublicKey)
  type Transfer = (PublicKey,PublicKey,BigInt,Sid)
  type State = Map[Tx,BigInt]
  type LocalState = Map[String,BigInt]
  type MemPool = List[Transfer]
  type Tr = Double
  type Cert = (PublicKey,Rho,Pi,PublicKey,Party,Tr)
  type Block = (Hash,State,Slot,Cert,Rho,Pi,MalkinSignature,PublicKey)
  type Chain = List[Block]
}
