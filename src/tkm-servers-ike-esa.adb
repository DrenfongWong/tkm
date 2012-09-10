with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.isa;

with Tkm.Logger;
with Tkm.Utils;
with Tkm.Key_Derivation;

package body Tkm.Servers.Ike.Esa
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Create_First
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type)
   is
      Ae_Id     : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
      Initiator : constant Boolean := Tkmrpc.Contexts.ae.Has_initiator
        (Id        => Ae_Id,
         initiator => 1);
      Nonce_Loc : constant Tkmrpc.Types.Nonce_Type
        := Tkmrpc.Contexts.ae.get_nonce_loc (Id => Ae_Id);
      Nonce_Rem : constant Tkmrpc.Types.Nonce_Type
        := Tkmrpc.Contexts.ae.get_nonce_rem (Id => Ae_Id);
      Sk_D      : constant Tkmrpc.Types.Key_Type
        := Tkmrpc.Contexts.isa.get_sk_d (Id => Isa_Id);

      Enc_I, Enc_R, Int_I, Int_R : Tkmrpc.Types.Key_Type
        := Tkmrpc.Types.Null_Key_Type;
   begin
      L.Log (Message => "Creating new ESA context with ID" & Esa_Id'Img
             & " (Isa" & Isa_Id'Img & ", Sp" & Sp_Id'Img & ", Ea" & Ea_Id'Img
             & ", spi_loc" & Esp_Spi_Loc'Img & ", spi_rem" & Esp_Spi_Rem'Img
             & ")");

      Key_Derivation.Derive_Child_Keys
        (Sk_D    => Sk_D.Data (Sk_D.Data'First .. Sk_D.Size),
         Nonce_I => (if Initiator then
                     Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size)
                     else
                     Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size)),
         Nonce_R => (if Initiator then
                     Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size)
                     else
                     Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size)),
         Enc_I   => Enc_I,
         Enc_R   => Enc_R,
         Int_I   => Int_I,
         Int_R   => Int_R);

      L.Log (Message => "Enc_I " & Utils.To_Hex_String
             (Input => Enc_I.Data (Enc_I.Data'First .. Enc_I.Size)));
      L.Log (Message => "Enc_R " & Utils.To_Hex_String
             (Input => Enc_R.Data (Enc_R.Data'First .. Enc_R.Size)));
      L.Log (Message => "Int_I " & Utils.To_Hex_String
             (Input => Int_I.Data (Int_I.Data'First .. Int_I.Size)));
      L.Log (Message => "Int_R " & Utils.To_Hex_String
             (Input => Int_R.Data (Int_R.Data'First .. Int_R.Size)));
   end Create_First;

end Tkm.Servers.Ike.Esa;
