package crypto.ouroboros

import scala.math.BigInt
import io.iohk.iodb.ByteArrayWrapper

trait obTypes {
  type KesKey = (Tree[Array[Byte]],Tree[Array[Byte]],Array[Byte],Array[Byte],Array[Byte])
  type KesSignature = (Array[Byte],Array[Byte],Array[Byte])
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
  type Box = (Any,Sid,Sig,PublicKey)
  type Transaction = (PublicKeyW,PublicKeyW,BigInt,Sid,Int,Sig)
  type ChainRequest = (Slot,Int)
  type Ledger = List[Any]
  type State = Map[PublicKeyW,(BigInt,Boolean,Int)]
  type MemPool = Map[Sid,Transaction]
  type Cert = (PublicKey,Rho,Pi,PublicKey,Double)
  type Block = (Hash,Ledger,Slot,Cert,Rho,Pi,KesSignature,PublicKey,Int,Slot)
  type BlockId = (Slot,ByteArrayWrapper)
  type Chain = Array[BlockId]
  type ChainData = Array[Map[ByteArrayWrapper,Block]]
  type ChainHistory = Array[List[BlockId]]
}
