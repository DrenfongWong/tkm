with Tkmrpc.Contexts.Dh;
with Tkmrpc.Contexts.Nc;

with Tkm.Utils;
with Tkm.Logger;
with Tkm.Crypto.Hmac_Sha512;

package body Tkm.Servers.Ike.Isa
is

   package L renames Tkm.Logger;

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
      pragma Unreferenced (Ae_Id, Ia_Id, Sk_Ai, Sk_Ar, Sk_Ei, Sk_Er);

      Secret    : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc : Tkmrpc.Types.Nonce_Type;
   begin
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

         Prf         : Crypto.Hmac_Sha512.Context_Type;
         Skeyseed    : Tkmrpc.Types.Byte_Sequence
           (1 .. Crypto.Hmac_Sha512.Hash_Output_Length);
         Fixed_Nonce : Tkmrpc.Types.Byte_Sequence
           (1 .. Nonce_Rem.Size + Nonce_Loc.Size);
      begin
         if Initiator = 1 then
            Fixed_Nonce (Fixed_Nonce'First .. Nonce_Loc.Size)
              := Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size);
            Fixed_Nonce (Nonce_Loc.Size + 1 .. Fixed_Nonce'Last)
              := Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size);
         else
            Fixed_Nonce (Fixed_Nonce'First .. Nonce_Rem.Size)
              := Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size);
            Fixed_Nonce (Nonce_Rem.Size + 1 .. Fixed_Nonce'Last)
              := Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size);
         end if;

         Crypto.Hmac_Sha512.Init (Ctx => Prf,
                                  Key => Fixed_Nonce);
         Skeyseed := Crypto.Hmac_Sha512.Generate (Ctx  => Prf,
                                                  Data => Secret.Data);
         L.Log (Message => "SKEYSEED " & Utils.To_Hex_String
                (Input => Skeyseed));
      end;
   end Create;

end Tkm.Servers.Ike.Isa;
