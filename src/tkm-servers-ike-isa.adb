with Tkm.Logger;

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
      pragma Unreferenced (Ae_Id, Ia_Id, Nonce_Rem, Initiator, Spi_Loc,
                           Spi_Rem, Sk_Ai, Sk_Ar, Sk_Ei, Sk_Er, Dh_Id,
                           Nc_Loc_Id);
   begin
      L.Log (Message => "Creating new ISA context (ID" & Isa_Id'Img & ")");
   end Create;

end Tkm.Servers.Ike.Isa;
