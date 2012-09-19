with Tkmrpc.Contexts.dh;
with Tkmrpc.Contexts.nc;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.ae;

with Tkm.Config;
with Tkm.Utils;
with Tkm.Logger;
with Tkm.Crypto.Hmac_Sha512;
with Tkm.Crypto.Prf_Plus_Hmac_Sha512;

package body Tkm.Servers.Ike.Isa
is

   package L renames Tkm.Logger;

   Key_Pad : constant String := "Key Pad for IKEv2";
   Sig_Rem : Tkmrpc.Types.Signature_Type;

   -------------------------------------------------------------------------

   procedure Auth_Psk
     (Isa_Id    : Tkmrpc.Types.Isa_Id_Type;
      Signature : Tkmrpc.Types.Signature_Type)
   is
      use type Tkmrpc.Types.Byte_Sequence;
   begin
      L.Log (Message => "Authenticating ISA context with ID" & Isa_Id'Img);
      if Signature.Data (Signature.Data'First .. Signature.Size)
        /= Sig_Rem.Data (Sig_Rem.Data'First .. Sig_Rem.Size)
      then
         raise Authentication_Failure with "Authentication failed for ISA"
           & " context" & Isa_Id'Img;
      end if;

      Tkmrpc.Contexts.ae.authenticate
        (Id              => Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id),
         ca_context      => 1,
         ra_id           => 1,
         remote_identity => 1,
         not_before      => 1,
         not_after       => 1);
      L.Log (Message => "Authentication of ISA context" & Isa_Id'Img
             & " successful");
   end Auth_Psk;

   -------------------------------------------------------------------------

   procedure Create
     (Isa_Id    :     Tkmrpc.Types.Isa_Id_Type;
      Ae_Id     :     Tkmrpc.Types.Ae_Id_Type;
      Ia_Id     :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id     :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem :     Tkmrpc.Types.Nonce_Type;
      Initiator :     Tkmrpc.Types.Init_Type;
      Spi_Loc   :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem   :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai     : out Tkmrpc.Types.Key_Type;
      Sk_Ar     : out Tkmrpc.Types.Key_Type;
      Sk_Ei     : out Tkmrpc.Types.Key_Type;
      Sk_Er     : out Tkmrpc.Types.Key_Type)
   is
      Int_Key_Len : constant := 64;
      Enc_Key_Len : constant := 32;
      Secret      : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc   : Tkmrpc.Types.Nonce_Type;

      Sk_D, Sk_Pi, Sk_Pr : Tkmrpc.Types.Key_Type :=
        (Size => Crypto.Hmac_Sha512.Hash_Output_Length,
         Data => (others => 0));
   begin
      Sk_Ai := Tkmrpc.Types.Null_Key_Type;
      Sk_Ar := Tkmrpc.Types.Null_Key_Type;
      Sk_Ei := Tkmrpc.Types.Null_Key_Type;
      Sk_Er := Tkmrpc.Types.Null_Key_Type;

      L.Log (Message => "Creating new ISA context with ID" & Isa_Id'Img
             & " (DH" & Dh_Id'Img & ", nonce" & Nc_Loc_Id'Img & ", spi_loc"
             & Spi_Loc'Img & ", spi_rem" & Spi_Rem'Img & ")");

      Tkmrpc.Contexts.dh.consume (Id     => Dh_Id,
                                  dh_key => Secret);
      L.Log (Message => "DH context" & Dh_Id'Img & " consumed");

      Tkmrpc.Contexts.nc.consume (Id    => Nc_Loc_Id,
                                  nonce => Nonce_Loc);
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

         --  SKEYSEED    = prf (Ni | Nr, Shared_Secret)
         --  PRFPLUSSEED = Ni | Nr | SPIi | SPIr

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

         Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)
           := Crypto.Prf_Plus_Hmac_Sha512.Generate
             (Ctx    => Prf_Plus,
              Length => Sk_D.Size);
         L.Log (Message => "Sk_D  " & Utils.To_Hex_String
                (Input => Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)));

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

         Sk_Pi.Data (Sk_Pi.Data'First .. Sk_Pi.Size)
           := Crypto.Prf_Plus_Hmac_Sha512.Generate
             (Ctx    => Prf_Plus,
              Length => Sk_Pi.Size);
         Sk_Pr.Data (Sk_Pr.Data'First .. Sk_Pr.Size)
           := Crypto.Prf_Plus_Hmac_Sha512.Generate
             (Ctx    => Prf_Plus,
              Length => Sk_Pr.Size);
         L.Log (Message => "Sk_Pi " & Utils.To_Hex_String
                (Input => Sk_Pi.Data (Sk_Pi.Data'First .. Sk_Pi.Size)));
         L.Log (Message => "Sk_Pr " & Utils.To_Hex_String
                (Input => Sk_Pr.Data (Sk_Pr.Data'First .. Sk_Pr.Size)));

         --  Create ae and isa contexts

         L.Log (Message => "Creating new AE context with ID" & Ae_Id'Img);
         Tkmrpc.Contexts.ae.create
           (Id              => Ae_Id,
            iag_id          => 1,
            dhag_id         => 1,
            creation_time   => 0,
            initiator       => Initiator,
            sk_ike_auth_loc => (if Initiator = 1 then Sk_Pi else Sk_Pr),
            sk_ike_auth_rem => (if Initiator = 0 then Sk_Pi else Sk_Pr),
            nonce_loc       => Nonce_Loc,
            nonce_rem       => Nonce_Rem);
         Tkmrpc.Contexts.isa.create
           (Id            => Isa_Id,
            ae_id         => Ae_Id,
            ia_id         => Ia_Id,
            sk_d          => Sk_D,
            creation_time => 0);
      end;
   end Create;

   -------------------------------------------------------------------------

   procedure Create_Child
     (Isa_Id        :     Tkmrpc.Types.Isa_Id_Type;
      Parent_Isa_Id :     Tkmrpc.Types.Isa_Id_Type;
      Ia_Id         :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id         :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id     :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem     :     Tkmrpc.Types.Nonce_Type;
      Initiator     :     Tkmrpc.Types.Init_Type;
      Spi_Loc       :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem       :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai         : out Tkmrpc.Types.Key_Type;
      Sk_Ar         : out Tkmrpc.Types.Key_Type;
      Sk_Ei         : out Tkmrpc.Types.Key_Type;
      Sk_Er         : out Tkmrpc.Types.Key_Type)
   is
      Int_Key_Len : constant := 64;
      Enc_Key_Len : constant := 32;
      Ae_Id       : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Parent_Isa_Id);
      Old_Sk_D    : constant Tkmrpc.Types.Key_Type
        := Tkmrpc.Contexts.isa.get_sk_d (Id => Parent_Isa_Id);

      Dh_Secret   : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc   : Tkmrpc.Types.Nonce_Type;
      Sk_D        : Tkmrpc.Types.Key_Type
        := (Size => Crypto.Hmac_Sha512.Hash_Output_Length,
            Data => (others => 0));
   begin
      Sk_Ai := Tkmrpc.Types.Null_Key_Type;
      Sk_Ar := Tkmrpc.Types.Null_Key_Type;
      Sk_Ei := Tkmrpc.Types.Null_Key_Type;
      Sk_Er := Tkmrpc.Types.Null_Key_Type;

      L.Log (Message => "Creating new child ISA context with ID" & Isa_Id'Img
             & " (Parent Isa" & Parent_Isa_Id'Img & ", DH" & Dh_Id'Img
             & ", nonce" & Nc_Loc_Id'Img & ", spi_loc" & Spi_Loc'Img
             & ", spi_rem" & Spi_Rem'Img & ")");

      Tkmrpc.Contexts.dh.consume (Id     => Dh_Id,
                                  dh_key => Dh_Secret);
      L.Log (Message => "DH context" & Dh_Id'Img & " consumed");

      Tkmrpc.Contexts.nc.consume (Id    => Nc_Loc_Id,
                                  nonce => Nonce_Loc);
      L.Log (Message => "Nonce context" & Nc_Loc_Id'Img & " consumed");

      --  Use PRF-HMAC-SHA512 for now.

      declare
         use type Tkmrpc.Types.Init_Type;

         Prf           : Crypto.Hmac_Sha512.Context_Type;
         Skeyseed      : Tkmrpc.Types.Byte_Sequence
           (1 .. Crypto.Hmac_Sha512.Hash_Output_Length);
         Sk_Seed       : Tkmrpc.Types.Byte_Sequence
           (1 .. Dh_Secret.Size + Nonce_Loc.Size + Nonce_Rem.Size);
         Seed_Size     : constant Tkmrpc.Types.Byte_Sequence_Range
           := Nonce_Rem.Size + Nonce_Loc.Size + 16;
         Prf_Plus_Seed : Tkmrpc.Types.Byte_Sequence (1 .. Seed_Size);
         Prf_Plus      : Crypto.Prf_Plus_Hmac_Sha512.Context_Type;
         PPS_Idx1      : constant Tkmrpc.Types.Byte_Sequence_Range
           := Nonce_Loc.Size + Nonce_Rem.Size + 1;
         --  PRFPLUSSEED index of SPIi start
         PPS_Idx2      : constant Tkmrpc.Types.Byte_Sequence_Range
           := PPS_Idx1 + 8;
         --  PRFPLUSSEED index of SPIr start
         Sks_Idx1      : constant Tkmrpc.Types.Byte_Sequence_Range
           := Dh_Secret.Size + 1;
         --  SKEYSEED index of Ni start
         Sks_Idx2      : Tkmrpc.Types.Byte_Sequence_Range;
         --  SKEYSEED index of Nr start
      begin

         --  SKEYSEED    = prf (SK_d (old), Shared_Secret | Ni | Nr)
         --  PRFPLUSSEED = Ni | Nr | SPIi | SPIr

         Sk_Seed (Sk_Seed'First .. Dh_Secret.Size)
           := Dh_Secret.Data (Dh_Secret.Data'First .. Dh_Secret.Size);
         if Initiator = 1 then
            Sks_Idx2 := Sks_Idx1 + Nonce_Loc.Size;
            Sk_Seed (Sks_Idx1 .. Sks_Idx2 - 1)
              := Nonce_Loc.Data  (Nonce_Loc.Data'First .. Nonce_Loc.Size);
            Sk_Seed (Sks_Idx2 .. Sk_Seed'Last)
              := Nonce_Rem.Data  (Nonce_Rem.Data'First .. Nonce_Rem.Size);
            Prf_Plus_Seed (Prf_Plus_Seed'First .. PPS_Idx1 - 1)
              := Sk_Seed (Sks_Idx1 .. Sk_Seed'Last);
            Prf_Plus_Seed (PPS_Idx1 .. PPS_Idx2 - 1)
              := Utils.To_Bytes (Input => Spi_Loc);
            Prf_Plus_Seed (PPS_Idx2 .. Prf_Plus_Seed'Last)
                := Utils.To_Bytes (Input => Spi_Rem);
         else
            Sks_Idx2 := Sks_Idx1 + Nonce_Rem.Size;
            Sk_Seed (Sks_Idx1 .. Sks_Idx2 - 1)
              := Nonce_Rem.Data  (Nonce_Rem.Data'First .. Nonce_Rem.Size);
            Sk_Seed (Sks_Idx2 .. Sk_Seed'Last)
              := Nonce_Loc.Data  (Nonce_Loc.Data'First .. Nonce_Loc.Size);
            Prf_Plus_Seed (Prf_Plus_Seed'First .. PPS_Idx1 - 1)
              := Sk_Seed (Sks_Idx1 .. Sk_Seed'Last);
            Prf_Plus_Seed (PPS_Idx1 .. PPS_Idx2 - 1)
              := Utils.To_Bytes (Input => Spi_Rem);
            Prf_Plus_Seed (PPS_Idx2 .. Prf_Plus_Seed'Last)
                := Utils.To_Bytes (Input => Spi_Loc);
         end if;

         Crypto.Hmac_Sha512.Init (Ctx => Prf,
                                  Key => Old_Sk_D.Data (1 .. Old_Sk_D.Size));
         Skeyseed := Crypto.Hmac_Sha512.Generate (Ctx  => Prf,
                                                  Data => Sk_Seed);
         L.Log (Message => "SKEYSEED " & Utils.To_Hex_String
                (Input => Skeyseed));
         L.Log (Message => "PRFPLUSSEED " & Utils.To_Hex_String
                (Input => Prf_Plus_Seed));

         --  KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr

         Crypto.Prf_Plus_Hmac_Sha512.Init (Ctx  => Prf_Plus,
                                           Key  => Skeyseed,
                                           Seed => Prf_Plus_Seed);

         --  Key for derivation of further (child) key material

         Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)
           := Crypto.Prf_Plus_Hmac_Sha512.Generate
             (Ctx    => Prf_Plus,
              Length => Sk_D.Size);
         L.Log (Message => "Sk_D  " & Utils.To_Hex_String
                (Input => Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)));

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

         --  Create isa context

         L.Log (Message => "Creating new ISA context with ID" & Isa_Id'Img);
         Tkmrpc.Contexts.isa.create
           (Id            => Isa_Id,
            ae_id         => Ae_Id,
            ia_id         => Ia_Id,
            sk_d          => Sk_D,
            creation_time => 0);
      end;
   end Create_Child;

   -------------------------------------------------------------------------

   procedure Reset (Isa_Id : Tkmrpc.Types.Isa_Id_Type)
   is
   begin
      L.Log (Message => "Resetting ISA context" & Isa_Id'Img);
      Tkmrpc.Contexts.isa.reset (Id => Isa_Id);
   end Reset;

   -------------------------------------------------------------------------

   procedure Sign_Psk
     (Isa_Id       :     Tkmrpc.Types.Isa_Id_Type;
      Init_Message :     Tkmrpc.Types.Init_Message_Type;
      Idx          :     Tkmrpc.Types.Idx_Type;
      Verify       :     Tkmrpc.Types.Verify_Type;
      Signature    : out Tkmrpc.Types.Signature_Type)
   is
      use type Tkmrpc.Types.Verify_Type;

      Sk_P  : Tkmrpc.Types.Key_Type;
      Nonce : Tkmrpc.Types.Nonce_Type;
      Prf   : Crypto.Hmac_Sha512.Context_Type;
      Ae_Id : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
   begin
      if Verify = 0 then
         L.Log (Message => "Generating local PSK signature");
         Sk_P  := Tkmrpc.Contexts.ae.get_sk_ike_auth_loc (Id => Ae_Id);
         Nonce := Tkmrpc.Contexts.ae.get_nonce_rem (Id => Ae_Id);
      else
         L.Log (Message => "Generating remote PSK signature");
         Sk_P  := Tkmrpc.Contexts.ae.get_sk_ike_auth_rem (Id => Ae_Id);
         Nonce := Tkmrpc.Contexts.ae.get_nonce_loc (Id => Ae_Id);
      end if;

      Crypto.Hmac_Sha512.Init
        (Ctx => Prf,
         Key => Sk_P.Data
           (Sk_P.Data'First .. Sk_P.Size));

      declare
         Octets : Tkmrpc.Types.Byte_Sequence
           (1 .. Init_Message.Size + Nonce.Size +
              Crypto.Hmac_Sha512.Hash_Output_Length);
      begin

         --  Octets = Init_Message | nonce | prf(Sk_p, Idx)

         Octets (1 .. Init_Message.Size)
           := Init_Message.Data (Init_Message.Data'First .. Init_Message.Size);
         Octets (Init_Message.Size + 1 .. Init_Message.Size + Nonce.Size)
           := Nonce.Data (Nonce.Data'First .. Nonce.Size);
         Octets (Init_Message.Size + Nonce.Size + 1 .. Octets'Last)
           := Crypto.Hmac_Sha512.Generate
             (Ctx  => Prf,
              Data => Idx.Data (Idx.Data'First .. Idx.Size));

         L.Log (Message => "AUTH Octets " & Utils.To_Hex_String
                (Input => Octets));

         --  Signature = prf(prf(Shared Secret,"Key Pad for IKEv2"), octets)

         Crypto.Hmac_Sha512.Init
           (Ctx => Prf,
            Key => Utils.To_Bytes (Input => Config.Pre_Shared_Key));
         Crypto.Hmac_Sha512.Init
           (Ctx => Prf,
            Key => Crypto.Hmac_Sha512.Generate
              (Ctx  => Prf,
               Data => Utils.To_Bytes (Input => Key_Pad)));

         declare
            Sig : constant Tkmrpc.Types.Byte_Sequence
              := Crypto.Hmac_Sha512.Generate (Ctx  => Prf,
                                              Data => Octets);
         begin
            Signature.Data (1 .. Sig'Length) := Sig;
            Signature.Size                   := Sig'Length;

            L.Log (Message => "PSK Signature " & Utils.To_Hex_String
                   (Input => Sig));
            if Verify = 1 then

               --  Store remote signature for AUTH step.

               Sig_Rem := Signature;
            else
               Tkmrpc.Contexts.ae.sign
                 (Id    => Ae_Id,
                  lc_id => 1);
            end if;
         end;
      end;
   end Sign_Psk;

end Tkm.Servers.Ike.Isa;
