package crypto.ouroboros

import scala.math.BigInt
import io.iohk.iodb.ByteArrayWrapper

trait obTypes {
  type MalkinKey = (Tree[Array[Byte]],Tree[Array[Byte]],Array[Byte],Array[Byte],Array[Byte])
  type MalkinSignature = (Array[Byte],Array[Byte],Array[Byte])
  type Eta = Array[Byte]
  type Sig = Array[Byte]
  type Slot = Int
  type Rho = Array[Byte]
  type PublicKey = Array[Byte]
  type Sid = ByteArrayWrapper
  type PublicKeyW = ByteArrayWrapper
  type PublicKeys = (PublicKey,PublicKey,PublicKey)
  type PrivateKey = Array[Byte]
  type Hash = ByteArrayWrapper
  type Pi = Array[Byte]
  type Tx = (Any,Sid,Sig,PublicKey)
  type Transfer = (PublicKeyW,PublicKeyW,BigInt,Sid,Int,Sig)
  type ChainRequest = (Slot,Int)
  type Ledger = List[Any]
  type LocalState = Map[PublicKeyW,(BigInt,Boolean,Int)]
  type MemPool = Map[Sid,Transfer]
  type Tr = Double
  type Cert = (PublicKey,Rho,Pi,PublicKey,Tr)
  type Block = (Hash,Ledger,Slot,Cert,Rho,Pi,MalkinSignature,PublicKey,Int,Slot)
  type BlockId = (Slot,ByteArrayWrapper)
  type Chain = Array[BlockId]
  type ChainData = Array[Map[ByteArrayWrapper,Block]]
}
