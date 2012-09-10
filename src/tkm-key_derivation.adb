with Tkm.Logger;
with Tkm.Crypto.Prf_Plus_Hmac_Sha512;
with Tkm.Utils;

package body Tkm.Key_Derivation
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Derive_Child_Keys
     (Sk_D    :     Tkmrpc.Types.Byte_Sequence;
      Nonce_I :     Tkmrpc.Types.Byte_Sequence;
      Nonce_R :     Tkmrpc.Types.Byte_Sequence;
      Enc_I   : out Tkmrpc.Types.Key_Type;
      Enc_R   : out Tkmrpc.Types.Key_Type;
      Int_I   : out Tkmrpc.Types.Key_Type;
      Int_R   : out Tkmrpc.Types.Key_Type)
   is
      Int_Key_Len : constant := 64;
      Enc_Key_Len : constant := 32;
      Seed_Size   : constant Positive := Nonce_I'Length + Nonce_R'Length;
      Seed        : Tkmrpc.Types.Byte_Sequence (1 .. Seed_Size);
      Prf_Plus    : Crypto.Prf_Plus_Hmac_Sha512.Context_Type;
   begin

      --  Seed = Nonce_I | Nonce_R

      Seed (Seed'First .. Nonce_I'Length)    := Nonce_I;
      Seed (Nonce_I'Length + 1 .. Seed'Last) := Nonce_R;

      L.Log (Message => "Sk_D " & Utils.To_Hex_String (Input => Sk_D));
      L.Log (Message => "Seed " & Utils.To_Hex_String (Input => Seed));

      --  KEYMAT = encr_i | integ_i | encr_r | integ_r

      Crypto.Prf_Plus_Hmac_Sha512.Init (Ctx  => Prf_Plus,
                                        Key  => Sk_D,
                                        Seed => Seed);

      --  Initiator ESP keys

      Enc_I.Data (Enc_I.Data'First .. Enc_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Enc_Key_Len);
      Enc_I.Size := Enc_Key_Len;
      Int_I.Data (Int_I.Data'First .. Int_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Int_Key_Len);
      Int_I.Size := Int_Key_Len;

      --  Responder ESP keys

      Enc_R.Data (Enc_R.Data'First .. Enc_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Enc_Key_Len);
      Enc_R.Size := Enc_Key_Len;
      Int_R.Data (Int_R.Data'First .. Int_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Int_Key_Len);
      Int_R.Size := Int_Key_Len;
   end Derive_Child_Keys;

end Tkm.Key_Derivation;
