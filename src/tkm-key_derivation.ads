with Tkmrpc.Types;

package Tkm.Key_Derivation
is

   procedure Derive_Ike_Keys
     (Skeyseed :     Tkmrpc.Types.Byte_Sequence;
      Prf_Seed :     Tkmrpc.Types.Byte_Sequence;
      Sk_D     : in out Tkmrpc.Types.Key_Type;
      Sk_Ai    : in out Tkmrpc.Types.Key_Type;
      Sk_Ar    : in out Tkmrpc.Types.Key_Type;
      Sk_Ei    : in out Tkmrpc.Types.Key_Type;
      Sk_Er    : in out Tkmrpc.Types.Key_Type;
      Sk_Pi    : in out Tkmrpc.Types.Key_Type;
      Sk_Pr    : in out Tkmrpc.Types.Key_Type);
   --  Derive IKE pfs secret, encryption, integrity and authentication keys
   --  from given skeyseed and seed, as specified in RFC 5996, section 2.14.
   --  The length of the various Sk_* keys is specified by their Size field
   --  value.

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
