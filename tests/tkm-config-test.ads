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

package Tkm.Config.Test
is

   Alice_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 20,
         Data =>
           (16#61#, 16#6C#, 16#69#, 16#63#, 16#65#, 16#40#, 16#73#, 16#74#,
            16#72#, 16#6F#, 16#6E#, 16#67#, 16#73#, 16#77#, 16#61#, 16#6E#,
            16#2E#, 16#6F#, 16#72#, 16#67#, others => 0));
   --  alice@strongswan.org.

   Bob_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 18,
         Data =>
           (16#62#, 16#6f#, 16#62#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6f#,
            16#6e#, 16#67#, 16#73#, 16#77#, 16#61#, 16#6e#, 16#2e#, 16#6f#,
            16#72#, 16#67#, others => 0));
   --  bob@strongswan.org.

   Lifetime_Hard : constant := 60;
   --  ESP SA lifetime in seconds (hard).

   Lifetime_Soft : constant := 30;
   --  ESP SA lifetime in seconds (soft).

   Ref_Local_Ids : constant Identities.Local_Identities_Type (1 .. 1)
     := (1 => (Id   => 1,
               Name => Alice_Id));
   --  Reference local identities.

   Ref_Policies : constant Config.Security_Policies_Type (1 .. 2)
     := (1 => (Id              => 1,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 0, 2),
               Remote_Identity => Bob_Id,
               Remote_Addr     => (192, 168, 0, 3),
               Remote_Net      => (192, 168, 0, 3),
               Lifetime_Soft   => Lifetime_Soft,
               Lifetime_Hard   => Lifetime_Hard),
         2 => (Id            => 2,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 100, 0),
               Remote_Identity => Bob_Id,
               Remote_Addr     => (192, 168, 0, 4),
               Remote_Net      => (192, 168, 200, 0),
               Lifetime_Soft => Lifetime_Soft,
               Lifetime_Hard => Lifetime_Hard));
   --  Reference policies.

   Ref_Config   : constant Config.Config_Type
     := (Version         => Config.Version,
         Policy_Count    => Ref_Policies'Length,
         Policies        => Ref_Policies,
         Local_Ids_Count => Ref_Local_Ids'Length,
         L_Identities    => Ref_Local_Ids);
   --  Reference config.

   Ref_Ike_Cfg : constant String
     := ASCII.LF & "conn conn1" & ASCII.LF &
   "    reqid=1" & ASCII.LF &
   "    left=192.168.0.2" & ASCII.LF &
   "    leftid=alice@strongswan.org" & ASCII.LF &
   "    leftcert=aliceCert.pem" & ASCII.LF &
   "    right=192.168.0.3" & ASCII.LF &
   "    rightid=bob@strongswan.org" & ASCII.LF &
   "    lifetime=60" & ASCII.LF &
   "    margintime=30" & ASCII.LF &
   "    ike=aes256-sha512-modp4096!" & ASCII.LF &
   "    esp=aes256-sha512-modp4096!" & ASCII.LF &
   "    type=transport" & ASCII.LF &
   "    auto=route" & ASCII.LF &
   ASCII.LF & "conn conn2" & ASCII.LF &
   "    reqid=2" & ASCII.LF &
   "    left=192.168.0.2" & ASCII.LF &
   "    leftid=alice@strongswan.org" & ASCII.LF &
   "    leftcert=aliceCert.pem" & ASCII.LF &
   "    right=192.168.0.4" & ASCII.LF &
   "    rightid=bob@strongswan.org" & ASCII.LF &
   "    lifetime=60" & ASCII.LF &
   "    margintime=30" & ASCII.LF &
   "    ike=aes256-sha512-modp4096!" & ASCII.LF &
   "    esp=aes256-sha512-modp4096!" & ASCII.LF &
   "    type=transport" & ASCII.LF &
   "    auto=route" & ASCII.LF;

   procedure Load (Cfg : Config_Type);
   --  Load given config.

   procedure Init_Grammar (File : String);
   --  Initialize grammar.

end Tkm.Config.Test;
