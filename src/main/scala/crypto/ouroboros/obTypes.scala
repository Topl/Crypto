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
  type Sid = Array[Byte]
  type PublicKeys = (PublicKey,PublicKey,PublicKey)
  type PrivateKey = Array[Byte]
  type Hash = ByteArrayWrapper
  type Pi = Array[Byte]
  type Tx = (Array[Byte],Sid,Sig,PublicKey)
  type Transfer = (PublicKey,PublicKey,BigInt,Sid)
  type State = Map[Tx,BigInt]
  type LocalState = Map[ByteArrayWrapper,(BigInt,Boolean)]
  type MemPool = List[Transfer]
  type Tr = Double
  type Cert = (PublicKey,Rho,Pi,PublicKey,Tr)
  type Block = (Hash,State,Slot,Cert,Rho,Pi,MalkinSignature,PublicKey,Int,Slot)
  type Chain = Array[Block]
  type ChainData = Array[Map[ByteArrayWrapper,Block]]
}
