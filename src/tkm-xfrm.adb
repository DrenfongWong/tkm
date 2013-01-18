with Interfaces;

with Anet;

with Xfrm.Sockets;

with Tkm.Logger;

package body Tkm.Xfrm
is

   package L renames Tkm.Logger;
   package X renames Standard.Xfrm.Sockets;

   Sock : X.Xfrm_Socket_Type;
   --  Netlink/XFRM socket.

   -------------------------------------------------------------------------

   procedure Add_Policy (Policy : Config.Security_Policy_Type)
   is
   begin
      L.Log (Message => "Adding policy [" & Policy.Id'Img & ", "
             & Anet.To_String (Address => Policy.Local_Addr) & " => "
             & Anet.To_String (Address => Policy.Remote_Addr) & " ]");
      Sock.Add_Policy
        (Src       => Policy.Local_Addr,
         Dst       => Policy.Remote_Addr,
         Reqid     => Interfaces.Unsigned_32 (Policy.Id),
         Direction => X.Direction_Out);
      Sock.Add_Policy
        (Src       => Policy.Remote_Addr,
         Dst       => Policy.Local_Addr,
         Reqid     => Interfaces.Unsigned_32 (Policy.Id),
         Direction => X.Direction_In);
   end Add_Policy;

   -------------------------------------------------------------------------

   procedure Add_State
     (Policy_Id    : Tkmrpc.Types.Sp_Id_Type;
      SPI_In       : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out      : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key_In   : Tkmrpc.Types.Byte_Sequence;
      Enc_Key_Out  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_In  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_Out : Tkmrpc.Types.Byte_Sequence)
   is
      function To_Anet_Bytes
        (Item : Tkmrpc.Types.Byte_Sequence)
         return Anet.Byte_Array;
      --  Convert given byte sequence to Anet byte array.

      function To_Anet_Bytes
        (Item : Tkmrpc.Types.Byte_Sequence)
         return Anet.Byte_Array
      is
         Result : Anet.Byte_Array (Item'Range);
      begin
         for I in Result'Range loop
            Result (I) := Anet.Byte (Item (I));
         end loop;

         return Result;
      end To_Anet_Bytes;

      Policy : constant Config.Security_Policy_Type
        := Config.Get_Policy (Id => Policy_Id);
   begin
      L.Log (Message => "Adding SA [" & Policy.Id'Img & ", "
             & Anet.To_String (Address => Policy.Local_Addr) & " <=> "
             & Anet.To_String (Address => Policy.Remote_Addr)
             & ", SPI_in" & SPI_In'Img & ", SPI_out" & SPI_Out'Img
             & ", soft" & Policy.Lifetime_Soft'Img
             & ", hard" & Policy.Lifetime_Hard'Img & " ]");

      --  Add outbound state

      Sock.Add_State
        (Src           => Policy.Local_Addr,
         Dst           => Policy.Remote_Addr,
         Reqid         => Policy.Id,
         Spi           => SPI_Out,
         Enc_Key       => To_Anet_Bytes (Item => Enc_Key_Out),
         Enc_Alg       => "aes",
         Int_Key       => To_Anet_Bytes (Item => Auth_Key_Out),
         Int_Alg       => "hmac(sha512)",
         Lifetime_Soft => Policy.Lifetime_Soft,
         Lifetime_Hard => Policy.Lifetime_Hard);

      --  Add inbound state

      Sock.Add_State
        (Src           => Policy.Remote_Addr,
         Dst           => Policy.Local_Addr,
         Reqid         => Policy.Id,
         Spi           => SPI_In,
         Enc_Key       => To_Anet_Bytes (Item => Enc_Key_In),
         Enc_Alg       => "aes",
         Int_Key       => To_Anet_Bytes (Item => Auth_Key_In),
         Int_Alg       => "hmac(sha512)",
         Lifetime_Soft => Policy.Lifetime_Soft,
         Lifetime_Hard => Policy.Lifetime_Hard);
   end Add_State;

   -------------------------------------------------------------------------

   procedure Delete_State
     (Destination : String;
      SPI         : Tkmrpc.Types.Esp_Spi_Type)
   is
   begin
      L.Log (Message => "Deleting SA [ => " & Destination & ", SPI"
             & SPI'Img & " ]");
      Sock.Delete_State
        (Dst => Anet.To_IPv4_Addr (Str => Destination),
         Spi => SPI);
   end Delete_State;

   -------------------------------------------------------------------------

   procedure Flush is
   begin
      L.Log (Message => "Flushing SPD");
      Sock.Flush_Policies;
      L.Log (Message => "Flushing SAD");
      Sock.Flush_States;
   end Flush;

   -------------------------------------------------------------------------

   procedure Init
   is
   begin
      Sock.Init;
   end Init;

end Tkm.Xfrm;
