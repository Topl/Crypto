package crypto.forwardtypes

import scorex.crypto.signatures.SigningFunctions.Signature

object forwardTypes {
  type Cert = (Array[Byte],Int,Array[Byte],Signature)
  type ForwardSig = (Cert,Signature,Int)
}
