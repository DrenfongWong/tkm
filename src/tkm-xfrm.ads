with Tkmrpc.Types;

with Tkm.Config;

package Tkm.Xfrm
is

   procedure Init;
   --  Init XFRM package.

   procedure Flush;
   --  Flush XFRM policies and states.

   procedure Add_Policy (Policy : Config.Security_Policy_Type);
   --  Add XFRM policy for given security policy.

   procedure Add_State
     (Policy_Id    : Tkmrpc.Types.Sp_Id_Type;
      SPI_In       : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out      : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key_In   : Tkmrpc.Types.Byte_Sequence;
      Enc_Key_Out  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_In  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_Out : Tkmrpc.Types.Byte_Sequence);
   --  Add XFRM state for specified policy with given parameters.

   procedure Delete_State
     (Policy_Id : Tkmrpc.Types.Sp_Id_Type;
      SPI_In    : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out   : Tkmrpc.Types.Esp_Spi_Type);
   --  Delete XFRM state for specified policy with given parameters.

   Xfrm_Error : exception;

end Tkm.Xfrm;
