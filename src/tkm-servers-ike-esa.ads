with Tkmrpc.Types;

package Tkm.Servers.Ike.Esa
is

   procedure Create
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Dh_Id       : Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id   : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Tkmrpc.Types.Init_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters.

   procedure Create_First
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters.

   procedure Create_No_Pfs
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Nc_Loc_Id   : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Tkmrpc.Types.Init_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters without perfect
   --  forward secrecy.

   procedure Reset (Esa_Id : Tkmrpc.Types.Esa_Id_Type);
   --  Reset ESA context with given id.

   Policy_Violation : exception;

end Tkm.Servers.Ike.Esa;
