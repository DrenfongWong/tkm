with Tkmrpc.Types;

package Tkm.Xfrm
is

   procedure Init;
   --  Init XFRM package.

   procedure Flush;
   --  Flush XFRM policies and states.

   procedure Add_Policy
     (Source      : String;
      Destination : String);
   --  Add XFRM policy with given source and destination address.

   procedure Add_State
     (Source        : String;
      Destination   : String;
      SPI           : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key       : Tkmrpc.Types.Byte_Sequence;
      Auth_Key      : Tkmrpc.Types.Byte_Sequence;
      Lifetime_Soft : Tkmrpc.Types.Rel_Time_Type;
      Lifetime_Hard : Tkmrpc.Types.Rel_Time_Type);
   --  Add XFRM state with given parameters. Lifetimes are specified in
   --  seconds.

   procedure Delete_State
     (Destination : String;
      SPI         : Tkmrpc.Types.Esp_Spi_Type);
   --  Delete XFRM state with given parameters.

   Xfrm_Error : exception;

end Tkm.Xfrm;
