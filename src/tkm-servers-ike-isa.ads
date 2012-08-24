with Tkmrpc.Types;

package Tkm.Servers.Ike.Isa
is

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
      Sk_Er     : out Tkmrpc.Types.Key_Type);
   --  Create a new ISA context with given id and parameters. Return the
   --  computed authentication and encryption keys.

end Tkm.Servers.Ike.Isa;
