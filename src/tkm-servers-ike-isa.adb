with Tkmrpc.Contexts.Dh;
with Tkmrpc.Contexts.Nc;

with Tkm.Utils;
with Tkm.Logger;
with Tkm.Crypto.Hmac_Sha512;
with Tkm.Crypto.Prf_Plus_Hmac_Sha512;

package body Tkm.Servers.Ike.Isa
is

   package L renames Tkm.Logger;

   Sk_d, Sk_Pi, Sk_Pr : Tkmrpc.Types.Byte_Sequence
     (1 .. Crypto.Hmac_Sha512.Hash_Output_Length);

   -------------------------------------------------------------------------

   procedure Create
     (Isa_Id    : Tkmrpc.Types.Isa_Id_Type;
      Ae_Id     : Tkmrpc.Types.Ae_Id_Type;
      Ia_Id     : Tkmrpc.Types.Ia_Id_Type;
      Dh_Id     : Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem : Tkmrpc.Types.Nonce_Type;
      Initiator : Tkmrpc.Types.Init_Type;
      Spi_Loc   : Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem   : Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai     : out Tkmrpc.Types.Key_Type;
      Sk_Ar     : out Tkmrpc.Types.Key_Type;
      Sk_Ei     : out Tkmrpc.Types.Key_Type;
      Sk_Er     : out Tkmrpc.Types.Key_Type)
   is
      pragma Unreferenced (Ae_Id, Ia_Id);

      Int_Key_Len : constant := 64;
      Enc_Key_Len : constant := 32;
      Secret      : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc   : Tkmrpc.Types.Nonce_Type;
   begin
      Sk_Ai := Tkmrpc.Types.Null_Key_Type;
      Sk_Ar := Tkmrpc.Types.Null_Key_Type;
      Sk_Ei := Tkmrpc.Types.Null_Key_Type;
      Sk_Er := Tkmrpc.Types.Null_Key_Type;

      L.Log (Message => "Creating new ISA context with ID" & Isa_Id'Img
             & " (DH" & Dh_Id'Img & ", nonce" & Nc_Loc_Id'Img & ", spi_loc"
             & Spi_Loc'Img & ", spi_rem" & Spi_Rem'Img & ")");

      --  TODO: Use DH consume here, but this is not yet possible because
      --        charon does key derivation twice at the moment (using the
      --        ikev2 keymat proxy).

      Secret := Tkmrpc.Contexts.Dh.Get_Shared_Secret (Id => Dh_Id);
--        Tkmrpc.Contexts.Dh.Consume (Id     => Dh_Id,
--                                    Dh_Key => Secret);
--        L.Log (Message => "DH context" & Dh_Id'Img & " consumed");

      Tkmrpc.Contexts.Nc.Consume (Id    => Nc_Loc_Id,
                                  Nonce => Nonce_Loc);
      L.Log (Message => "Nonce context" & Nc_Loc_Id'Img & " consumed");

      --  Use PRF-HMAC-SHA512 for now.

      declare
         use type Tkmrpc.Types.Init_Type;

         Prf           : Crypto.Hmac_Sha512.Context_Type;
         Skeyseed      : Tkmrpc.Types.Byte_Sequence
           (1 .. Crypto.Hmac_Sha512.Hash_Output_Length);
         Fixed_Nonce   : Tkmrpc.Types.Byte_Sequence
           (1 .. Nonce_Rem.Size + Nonce_Loc.Size);
         Seed_Size     : constant Positive := Nonce_Rem.Size + Nonce_Loc.Size
           + 16;
         Prf_Plus_Seed : Tkmrpc.Types.Byte_Sequence (1 .. Seed_Size);
         Prf_Plus      : Crypto.Prf_Plus_Hmac_Sha512.Context_Type;
      begin
         if Initiator = 1 then
            Fixed_Nonce (Fixed_Nonce'First .. Nonce_Loc.Size)
              := Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size);
            Fixed_Nonce (Nonce_Loc.Size + 1 .. Fixed_Nonce'Last)
              := Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size);
            Prf_Plus_Seed (1 .. Nonce_Rem.Size + Nonce_Loc.Size)
              := Fixed_Nonce;
            Prf_Plus_Seed
              (Nonce_Rem.Size + Nonce_Loc.Size + 1 .. Nonce_Rem.Size
               + Nonce_Loc.Size + 8)
              := Utils.To_Bytes (Input => Spi_Loc);
            Prf_Plus_Seed
              (Nonce_Rem.Size + Nonce_Loc.Size + 9 ..
                 Prf_Plus_Seed'Last)
                := Utils.To_Bytes (Input => Spi_Rem);
         else
            Fixed_Nonce (Fixed_Nonce'First .. Nonce_Rem.Size)
              := Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size);
            Fixed_Nonce (Nonce_Rem.Size + 1 .. Fixed_Nonce'Last)
              := Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size);
            Prf_Plus_Seed (1 .. Nonce_Rem.Size + Nonce_Loc.Size)
              := Fixed_Nonce;
            Prf_Plus_Seed
              (Nonce_Rem.Size + Nonce_Loc.Size + 1 .. Nonce_Rem.Size
               + Nonce_Loc.Size + 8)
              := Utils.To_Bytes (Input => Spi_Rem);
            Prf_Plus_Seed
              (Nonce_Rem.Size + Nonce_Loc.Size + 9 ..
                 Prf_Plus_Seed'Last)
                := Utils.To_Bytes (Input => Spi_Loc);
         end if;

         Crypto.Hmac_Sha512.Init (Ctx => Prf,
                                  Key => Fixed_Nonce);
         Skeyseed := Crypto.Hmac_Sha512.Generate (Ctx  => Prf,
                                                  Data => Secret.Data);
         L.Log (Message => "SKEYSEED " & Utils.To_Hex_String
                (Input => Skeyseed));
         L.Log (Message => "PRFPLUSSEED " & Utils.To_Hex_String
                (Input => Prf_Plus_Seed));

         --  KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr

         Crypto.Prf_Plus_Hmac_Sha512.Init (Ctx  => Prf_Plus,
                                           Key  => Skeyseed,
                                           Seed => Prf_Plus_Seed);

         --  Key for derivation of further (child) key material

         Sk_d := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Sk_d'Length);
         L.Log (Message => "Sk_d  " & Utils.To_Hex_String (Input => Sk_d));

         --  IKE authentication keys

         Sk_Ai.Data (1 .. Int_Key_Len) := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Int_Key_Len);
         Sk_Ai.Size := Int_Key_Len;
         Sk_Ar.Data (1 .. Int_Key_Len) := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Int_Key_Len);
         Sk_Ar.Size := Int_Key_Len;
         L.Log (Message => "Sk_Ai " & Utils.To_Hex_String
                (Input => Sk_Ai.Data (1 .. Sk_Ai.Size)));
         L.Log (Message => "Sk_Ar " & Utils.To_Hex_String
                (Input => Sk_Ar.Data (1 .. Sk_Ar.Size)));

         --  IKE encryption keys

         Sk_Ei.Data (1 .. Enc_Key_Len) := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Enc_Key_Len);
         Sk_Ei.Size := Enc_Key_Len;
         Sk_Er.Data (1 .. Enc_Key_Len) := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Enc_Key_Len);
         Sk_Er.Size := Enc_Key_Len;
         L.Log (Message => "Sk_Ei " & Utils.To_Hex_String
                (Input => Sk_Ei.Data (1 .. Sk_Ei.Size)));
         L.Log (Message => "Sk_Er " & Utils.To_Hex_String
                (Input => Sk_Er.Data (1 .. Sk_Er.Size)));

         --  Keys used for AUTH payload generation

         Sk_Pi := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Sk_Pi'Length);
         Sk_Pr := Crypto.Prf_Plus_Hmac_Sha512.Generate
           (Ctx    => Prf_Plus,
            Length => Sk_Pr'Length);
         L.Log (Message => "Sk_Pi " & Utils.To_Hex_String (Input => Sk_Pi));
         L.Log (Message => "Sk_Pr " & Utils.To_Hex_String (Input => Sk_Pr));
      end;
   end Create;

end Tkm.Servers.Ike.Isa;
