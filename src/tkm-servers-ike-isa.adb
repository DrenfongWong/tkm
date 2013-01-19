with X509.Keys;
with X509.Certs;

with Tkmrpc.Contexts.dh;
with Tkmrpc.Contexts.nc;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.cc;

with Tkm.Config;
with Tkm.Utils;
with Tkm.Logger;
with Tkm.Key_Derivation;
with Tkm.Private_Key;
with Tkm.Crypto.Hmac_Sha512;
with Tkm.Crypto.Rsa_Pkcs1_Sha1;

package body Tkm.Servers.Ike.Isa
is

   package L renames Tkm.Logger;

   Int_Key_Len : constant := 64;
   Enc_Key_Len : constant := 32;

   function Compute_Auth_Octets
     (Ae_Id        : Tkmrpc.Types.Ae_Id_Type;
      Init_Message : Tkmrpc.Types.Init_Message_Type;
      Idx          : Tkmrpc.Types.Identity_Type;
      Verify       : Boolean)
      return Tkmrpc.Types.Byte_Sequence;
   --  Compute local/remote AUTH octets for given AE context depending on the
   --  verify flag: Verify = False => local.

   -------------------------------------------------------------------------

   procedure Auth
     (Isa_Id       : Tkmrpc.Types.Isa_Id_Type;
      Cc_Id        : Tkmrpc.Types.Cc_Id_Type;
      Init_Message : Tkmrpc.Types.Init_Message_Type;
      Signature    : Tkmrpc.Types.Signature_Type)
   is
      package RSA renames Crypto.Rsa_Pkcs1_Sha1;

      Raw_Cert  : constant Tkmrpc.Types.Certificate_Type
        := Tkmrpc.Contexts.cc.get_certificate (Id => Cc_Id);
      User_Cert : X509.Certs.Certificate_Type;
   begin
      X509.Certs.Load
        (Buffer => Utils.To_X509_Bytes
           (Item => Raw_Cert.Data (Raw_Cert.Data'First .. Raw_Cert.Size)),
         Cert   => User_Cert);
      L.Log (Message => "Verifying remote signature for ISA context"
             & Isa_Id'Img & " with CC context" & Cc_Id'Img);

      declare
         Pubkey   : constant X509.Keys.RSA_Public_Key_Type
           := X509.Certs.Get_Public_Key (Cert => User_Cert);
         Verifier : RSA.Verifier_Type;
         Ae_Id    : constant Tkmrpc.Types.Ae_Id_Type
           := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
         Octets   : constant Tkmrpc.Types.Byte_Sequence
           := Compute_Auth_Octets (Ae_Id        => Ae_Id,
                                   Init_Message => Init_Message,
                                   Idx          => Config.Remote_Id,
                                   Verify       => True);
      begin
         RSA.Init (Ctx => Verifier,
                   N   => X509.Keys.Get_Modulus (Key => Pubkey),
                   E   => X509.Keys.Get_Pub_Exponent (Key => Pubkey));

         if not RSA.Verify
           (Ctx       => Verifier,
            Data      => Octets,
            Signature => Signature.Data
              (Signature.Data'First .. Signature.Size))
         then
            raise Authentication_Failure with "Authentication failed for ISA"
              & " context" & Isa_Id'Img;
         end if;

         Tkmrpc.Contexts.ae.authenticate
           (Id         => Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id),
            ca_context => 1,
            authag_id  => 1,
            ri_id      => 1,
            not_before => 1,
            not_after  => 1);
         L.Log (Message => "Authentication of ISA context" & Isa_Id'Img
                & " successful");
      end;
   end Auth;

   -------------------------------------------------------------------------

   function Compute_Auth_Octets
     (Ae_Id        : Tkmrpc.Types.Ae_Id_Type;
      Init_Message : Tkmrpc.Types.Init_Message_Type;
      Idx          : Tkmrpc.Types.Identity_Type;
      Verify       : Boolean)
      return Tkmrpc.Types.Byte_Sequence
   is
      Sk_P  : Tkmrpc.Types.Key_Type;
      Nonce : Tkmrpc.Types.Nonce_Type;
      Prf   : Crypto.Hmac_Sha512.Context_Type;
   begin
      if Verify then
         L.Log (Message => "Generating remote AUTH octets");
         Sk_P  := Tkmrpc.Contexts.ae.get_sk_ike_auth_rem (Id => Ae_Id);
         Nonce := Tkmrpc.Contexts.ae.get_nonce_loc (Id => Ae_Id);
      else
         L.Log (Message => "Generating local AUTH octets");
         Sk_P  := Tkmrpc.Contexts.ae.get_sk_ike_auth_loc (Id => Ae_Id);
         Nonce := Tkmrpc.Contexts.ae.get_nonce_rem (Id => Ae_Id);
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
         return Octets;
      end;
   end Compute_Auth_Octets;

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
      Secret    : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc : Tkmrpc.Types.Nonce_Type;

      Sk_D, Sk_Pi, Sk_Pr : Tkmrpc.Types.Key_Type :=
        (Size => Crypto.Hmac_Sha512.Hash_Output_Length,
         Data => (others => 0));
   begin
      Sk_Ai := (Size => Int_Key_Len,
                Data => (others => 0));
      Sk_Ar := (Size => Int_Key_Len,
                Data => (others => 0));
      Sk_Ei := (Size => Enc_Key_Len,
                Data => (others => 0));
      Sk_Er := (Size => Enc_Key_Len,
                Data => (others => 0));

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

         Key_Derivation.Derive_Ike_Keys (Skeyseed => Skeyseed,
                                         Prf_Seed => Prf_Plus_Seed,
                                         Sk_D     => Sk_D,
                                         Sk_Ai    => Sk_Ai,
                                         Sk_Ar    => Sk_Ar,
                                         Sk_Ei    => Sk_Ei,
                                         Sk_Er    => Sk_Er,
                                         Sk_Pi    => Sk_Pi,
                                         Sk_Pr    => Sk_Pr);

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
      Ae_Id     : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Parent_Isa_Id);
      Old_Sk_D  : constant Tkmrpc.Types.Key_Type
        := Tkmrpc.Contexts.isa.get_sk_d (Id => Parent_Isa_Id);

      Dh_Secret : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc : Tkmrpc.Types.Nonce_Type;
      Sk_D      : Tkmrpc.Types.Key_Type
        := (Size => Crypto.Hmac_Sha512.Hash_Output_Length,
            Data => (others => 0));
   begin
      Sk_Ai := (Size => Int_Key_Len,
                Data => (others => 0));
      Sk_Ar := (Size => Int_Key_Len,
                Data => (others => 0));
      Sk_Ei := (Size => Enc_Key_Len,
                Data => (others => 0));
      Sk_Er := (Size => Enc_Key_Len,
                Data => (others => 0));

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
         Sk_P          : Tkmrpc.Types.Key_Type := Tkmrpc.Types.Null_Key_Type;
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
         Key_Derivation.Derive_Ike_Keys (Skeyseed => Skeyseed,
                                         Prf_Seed => Prf_Plus_Seed,
                                         Sk_D     => Sk_D,
                                         Sk_Ai    => Sk_Ai,
                                         Sk_Ar    => Sk_Ar,
                                         Sk_Ei    => Sk_Ei,
                                         Sk_Er    => Sk_Er,
                                         Sk_Pi    => Sk_P,
                                         Sk_Pr    => Sk_P);

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

   procedure Sign
     (Isa_Id       :     Tkmrpc.Types.Isa_Id_Type;
      Lc_Id        :     Tkmrpc.Types.Lc_Id_Type;
      Init_Message :     Tkmrpc.Types.Init_Message_Type;
      Signature    : out Tkmrpc.Types.Signature_Type)
   is
      package RSA renames Crypto.Rsa_Pkcs1_Sha1;

      Privkey : constant X509.Keys.RSA_Private_Key_Type := Private_Key.Get;
      Signer  : RSA.Signer_Type;
      Ae_Id   : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
      Octets  : constant Tkmrpc.Types.Byte_Sequence
        := Compute_Auth_Octets
          (Ae_Id        => Ae_Id,
           Init_Message => Init_Message,
           Idx          => Config.Get_Local_Identity (Id => Lc_Id).Name,
           Verify       => False);
   begin
      L.Log (Message => "Generating local signature for ISA context"
             & Isa_Id'Img);

      RSA.Init (Ctx   => Signer,
                N     => X509.Keys.Get_Modulus (Key => Privkey),
                E     => X509.Keys.Get_Pub_Exponent (Key => Privkey),
                D     => X509.Keys.Get_Priv_Exponent (Key => Privkey),
                P     => X509.Keys.Get_Prime_P (Key => Privkey),
                Q     => X509.Keys.Get_Prime_Q (Key => Privkey),
                Exp1  => X509.Keys.Get_Exponent1 (Key => Privkey),
                Exp2  => X509.Keys.Get_Exponent2 (Key => Privkey),
                Coeff => X509.Keys.Get_Coefficient (Key => Privkey));

      declare
         Sig : constant Tkmrpc.Types.Byte_Sequence
           := RSA.Generate (Ctx  => Signer,
                            Data => Octets);
      begin
         Signature.Data (1 .. Sig'Length) := Sig;
         Signature.Size                   := Sig'Length;

         L.Log (Message => "Signature " & Utils.To_Hex_String
                (Input => Sig));
         Tkmrpc.Contexts.ae.sign
           (Id    => Ae_Id,
            lc_id => 1);
      end;
   end Sign;

   -------------------------------------------------------------------------

   procedure Skip_Create_First (Isa_Id : Tkmrpc.Types.Isa_Id_Type)
   is
      Ae_Id : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
   begin
      Tkmrpc.Contexts.ae.activate (Id => Ae_Id);
   end Skip_Create_First;

end Tkm.Servers.Ike.Isa;
