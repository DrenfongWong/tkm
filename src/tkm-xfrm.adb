--
--  Copyright (C) 2013  Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2013  Adrian-Ken Rueegsegger <ken@codelabs.ch>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

with Ada.Strings.Fixed;

with Anet;

with Xfrm.Sockets;

with Tkm.Logger;

package body Tkm.Xfrm
is

   package L renames Tkm.Logger;
   package X renames Standard.Xfrm.Sockets;

   Mode_Map : constant array (Config.Connection_Mode_Type) of X.Mode_Type
     := (Config.Tunnel    => X.Mode_Tunnel,
         Config.Transport => X.Mode_Transport);
   --  Connection mode mapping.

   Sock : X.Xfrm_Socket_Type;
   --  Netlink/XFRM socket.

   -------------------------------------------------------------------------

   procedure Add_Policy (Policy : Config.Security_Policy_Type)
   is
      use type Tkm.Config.Connection_Mode_Type;

      Sel_Loc        : Anet.IPv4_Addr_Type;
      Sel_Loc_Prefix : X.Prefix_Type;
      Sel_Rem        : Anet.IPv4_Addr_Type;
      Sel_Rem_Prefix : X.Prefix_Type;
      Tmpl_Loc       : Anet.IPv4_Addr_Type;
      Tmpl_Rem       : Anet.IPv4_Addr_Type;
   begin
      if Policy.Mode = Config.Tunnel then
         Sel_Loc        := Policy.Local_Net;
         Sel_Loc_Prefix := X.Prefix_Type (Policy.Local_Netmask);
         Sel_Rem        := Policy.Remote_Net;
         Sel_Rem_Prefix := X.Prefix_Type (Policy.Remote_Netmask);
         Tmpl_Loc       := Policy.Local_Addr;
         Tmpl_Rem       := Policy.Remote_Addr;
         L.Log (Message => "Adding policy [" & Policy.Id'Img & ", "
                & Anet.To_String (Address => Sel_Loc) & "/"
                & Ada.Strings.Fixed.Trim (Source => Sel_Loc_Prefix'Img,
                                          Side   => Ada.Strings.Left)
                & " > " & Anet.To_String (Address => Policy.Local_Addr)
                & " <=> "
                & Anet.To_String (Address => Policy.Remote_Addr) & " < "
                & Anet.To_String (Address => Sel_Rem) & "/"
                & Ada.Strings.Fixed.Trim (Source => Sel_Rem_Prefix'Img,
                                          Side   => Ada.Strings.Left)
                & " ]");
         Sock.Add_Policy
           (Mode           => Mode_Map (Policy.Mode),
            Sel_Src        => Sel_Rem,
            Sel_Src_Prefix => Sel_Rem_Prefix,
            Sel_Dst        => Sel_Loc,
            Sel_Dst_Prefix => Sel_Loc_Prefix,
            Tmpl_Src       => Tmpl_Rem,
            Tmpl_Dst       => Tmpl_Loc,
            Reqid          => Policy.Id,
            Direction      => X.Direction_Fwd);
      else
         Sel_Loc        := Policy.Local_Addr;
         Sel_Loc_Prefix := 32;
         Sel_Rem        := Policy.Remote_Addr;
         Sel_Rem_Prefix := 32;
         Tmpl_Loc       := Anet.Any_Addr;
         Tmpl_Rem       := Anet.Any_Addr;
         L.Log (Message => "Adding policy [" & Policy.Id'Img & ", "
                & Anet.To_String (Address => Policy.Local_Addr) & " <-> "
                & Anet.To_String (Address => Policy.Remote_Addr) & " ]");
      end if;

      Sock.Add_Policy
        (Mode           => Mode_Map (Policy.Mode),
         Sel_Src        => Sel_Loc,
         Sel_Src_Prefix => Sel_Loc_Prefix,
         Sel_Dst        => Sel_Rem,
         Sel_Dst_Prefix => Sel_Rem_Prefix,
         Tmpl_Src       => Tmpl_Loc,
         Tmpl_Dst       => Tmpl_Rem,
         Reqid          => Policy.Id,
         Direction      => X.Direction_Out);
      Sock.Add_Policy
        (Mode           => Mode_Map (Policy.Mode),
         Sel_Src        => Sel_Rem,
         Sel_Src_Prefix => Sel_Rem_Prefix,
         Sel_Dst        => Sel_Loc,
         Sel_Dst_Prefix => Sel_Loc_Prefix,
         Tmpl_Src       => Tmpl_Rem,
         Tmpl_Dst       => Tmpl_Loc,
         Reqid          => Policy.Id,
         Direction      => X.Direction_In);
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
      use type Tkm.Config.Connection_Mode_Type;

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

      Sel_Loc        : Anet.IPv4_Addr_Type;
      Sel_Loc_Prefix : X.Prefix_Type;
      Sel_Rem        : Anet.IPv4_Addr_Type;
      Sel_Rem_Prefix : X.Prefix_Type;
   begin
      if Policy.Mode = Config.Tunnel then
         Sel_Loc        := Policy.Local_Net;
         Sel_Loc_Prefix := X.Prefix_Type (Policy.Local_Netmask);
         Sel_Rem        := Policy.Remote_Net;
         Sel_Rem_Prefix := X.Prefix_Type (Policy.Remote_Netmask);
         L.Log (Message => "Adding SA [" & Policy.Id'Img & ", "
                & Anet.To_String (Address => Sel_Loc) & "/"
                & Ada.Strings.Fixed.Trim (Source => Sel_Loc_Prefix'Img,
                                          Side   => Ada.Strings.Left)
                & " > " & Anet.To_String (Address => Policy.Local_Addr)
                & " <=> "
                & Anet.To_String (Address => Policy.Remote_Addr) & " < "
                & Anet.To_String (Address => Sel_Rem) & "/"
                & Ada.Strings.Fixed.Trim (Source => Sel_Rem_Prefix'Img,
                                          Side   => Ada.Strings.Left)
                & ", SPI_in" & SPI_In'Img & ", SPI_out" & SPI_Out'Img
                & ", soft" & Policy.Lifetime_Soft'Img
                & ", hard" & Policy.Lifetime_Hard'Img & " ]");
      else
         Sel_Loc        := Policy.Local_Addr;
         Sel_Loc_Prefix := 32;
         Sel_Rem        := Policy.Remote_Addr;
         Sel_Rem_Prefix := 32;
         L.Log (Message => "Adding SA [" & Policy.Id'Img & ", "
                & Anet.To_String (Address => Policy.Local_Addr) & " <-> "
                & Anet.To_String (Address => Policy.Remote_Addr)
                & ", SPI_in" & SPI_In'Img & ", SPI_out" & SPI_Out'Img
                & ", soft" & Policy.Lifetime_Soft'Img
                & ", hard" & Policy.Lifetime_Hard'Img & " ]");
      end if;

      --  Add outbound state

      Sock.Add_State
        (Mode           => Mode_Map (Policy.Mode),
         Src            => Policy.Local_Addr,
         Dst            => Policy.Remote_Addr,
         Sel_Src        => Sel_Loc,
         Sel_Src_Prefix => Sel_Loc_Prefix,
         Sel_Dst        => Sel_Rem,
         Sel_Dst_Prefix => Sel_Rem_Prefix,
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
        (Mode           => Mode_Map (Policy.Mode),
         Src            => Policy.Remote_Addr,
         Dst            => Policy.Local_Addr,
         Sel_Src        => Sel_Rem,
         Sel_Src_Prefix => Sel_Rem_Prefix,
         Sel_Dst        => Sel_Loc,
         Sel_Dst_Prefix => Sel_Loc_Prefix,
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
     (Policy_Id : Tkmrpc.Types.Sp_Id_Type;
      SPI_In    : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out   : Tkmrpc.Types.Esp_Spi_Type)
   is
      Policy : constant Config.Security_Policy_Type
        := Config.Get_Policy (Id => Policy_Id);
   begin
      L.Log (Message => "Deleting SA [" & Policy.Id'Img & ", "
             & Anet.To_String (Address => Policy.Local_Addr) & " <=> "
             & Anet.To_String (Address => Policy.Remote_Addr)
             & ", SPI_in" & SPI_In'Img & ", SPI_out" & SPI_Out'Img & " ]");

      --  Delete outbound state

      Sock.Delete_State
        (Dst => Policy.Remote_Addr,
         Spi => SPI_Out);

      --  Delete inbound state

      Sock.Delete_State
        (Dst => Policy.Local_Addr,
         Spi => SPI_In);
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
