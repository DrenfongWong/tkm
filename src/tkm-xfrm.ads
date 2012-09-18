with Tkmrpc.Types;

package Tkm.Xfrm
is

   procedure Flush;
   --  Flush XFRM policies and states.

   procedure Add_Policy
     (Source      : String;
      Destination : String);
   --  Add XFRM policy with given source and destination address.

   procedure Add_State
     (Source      : String;
      Destination : String;
      SPI         : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key     : Tkmrpc.Types.Byte_Sequence;
      Auth_Key    : Tkmrpc.Types.Byte_Sequence;
      Lifetime    : Tkmrpc.Types.Rel_Time_Type);
   --  Add XFRM state with given parameters. Lifetime is specified in seconds.

   procedure Delete_State
     (Source      : String;
      Destination : String;
      SPI         : Tkmrpc.Types.Esp_Spi_Type);
   --  Delete XFRM state with given parameters.

   Xfrm_Error : exception;

end Tkm.Xfrm;
