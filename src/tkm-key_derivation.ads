with Tkmrpc.Types;

package Tkm.Key_Derivation
is

   procedure Derive_Child_Keys
     (Sk_D    :     Tkmrpc.Types.Byte_Sequence;
      Secret  :     Tkmrpc.Types.Byte_Sequence;
      Nonce_I :     Tkmrpc.Types.Byte_Sequence;
      Nonce_R :     Tkmrpc.Types.Byte_Sequence;
      Enc_I   : out Tkmrpc.Types.Key_Type;
      Enc_R   : out Tkmrpc.Types.Key_Type;
      Int_I   : out Tkmrpc.Types.Key_Type;
      Int_R   : out Tkmrpc.Types.Key_Type);
   --  Derive encryption and integrity keys from given sk_d, DH secret and
   --  nonces, as specified in RFC 5996, section 2.17.

end Tkm.Key_Derivation;
