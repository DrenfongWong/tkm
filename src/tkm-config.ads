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

with Anet;

with Tkm.Identities;

package Tkm.Config
is

   Version : constant Tkmrpc.Types.Version_Type := 1;
   --  Config format version. Must be increased if structure of Config_Type
   --  changes.

   Max_Policy_Count : constant := 32;
   --  Maximum number of policies.

   Max_Local_Identities_Count : constant := 32;
   --  Maximum number of local identities.

   type Security_Policy_Type is record
      Id              : Tkmrpc.Types.Sp_Id_Type;
      Local_Identity  : Tkmrpc.Types.Li_Id_Type;
      Local_Addr      : Anet.IPv4_Addr_Type;
      Local_Net       : Anet.IPv4_Addr_Type;
      Local_Netmask   : Tkmrpc.Types.Byte;
      Remote_Identity : Tkmrpc.Types.Identity_Type;
      Remote_Addr     : Anet.IPv4_Addr_Type;
      Remote_Net      : Anet.IPv4_Addr_Type;
      Remote_Netmask  : Tkmrpc.Types.Byte;
      Lifetime_Soft   : Tkmrpc.Types.Abs_Time_Type;
      Lifetime_Hard   : Tkmrpc.Types.Abs_Time_Type;
   end record;
   --  Security policy describing a connection.

   Null_Security_Policy : constant Security_Policy_Type;

   type Security_Policies_Type is array (Positive range <>)
     of Security_Policy_Type;

   type Config_Type
     (Version         : Tkmrpc.Types.Version_Type;
      Policy_Count    : Positive;
      Local_Ids_Count : Positive)
   is record
      Policies     : Security_Policies_Type (1 .. Policy_Count);
      L_Identities : Identities.Local_Identities_Type (1 .. Local_Ids_Count);
   end record;
   --  TKM Configuration.

   function Read (Filename : String) return Config_Type;
   --  Load config from file specified by filename. An exception is raised if
   --  the version of the config read from the file differs from the one
   --  specified by the 'Version' constant.

   procedure Write
     (Config   : Config_Type;
      Filename : String);
   --  Write configuration to file specified by filename.

   procedure Load (Filename : String);
   --  Load config from given file.

   procedure Clear;
   --  Clear configuration.

   function Is_Empty return Boolean;
   --  Returns True if no configuration is present.

   function Get_Policy_Count return Natural;
   --  Returns number of policies present in current config.

   function Get_Policy
     (Id : Tkmrpc.Types.Sp_Id_Type)
      return Security_Policy_Type
   with
     Pre => not Is_Empty;
   --  Returns policy with given id from the config. A config error is raised
   --  if no policy with given id exists.

   function Get_Local_Identity
     (Id : Tkmrpc.Types.Li_Id_Type)
      return Identities.Local_Identity_Type
   with
     Pre => not Is_Empty;
   --  Returns local identity with given id from the config. A config error is
   --  raised if no local identity with given id exists.

   procedure Iterate
     (Process : not null access procedure (Policy : Security_Policy_Type))
   with
     Pre => not Is_Empty;
   --  Calls the given process procedure for each policy in the config.

   Config_Error : exception;

private

   Null_Security_Policy : constant Security_Policy_Type
     := (Id              => Tkmrpc.Types.Sp_Id_Type'First,
         Local_Identity  => Tkmrpc.Types.Li_Id_Type'First,
         Local_Addr      => Anet.Any_Addr,
         Local_Net       => Anet.Any_Addr,
         Local_Netmask   => 0,
         Remote_Identity => Tkmrpc.Types.Null_Identity_Type,
         Remote_Addr     => Anet.Any_Addr,
         Remote_Net      => Anet.Any_Addr,
         Remote_Netmask  => 0,
         Lifetime_Soft   => Tkmrpc.Types.Abs_Time_Type'First,
         Lifetime_Hard   => Tkmrpc.Types.Abs_Time_Type'First);

   Policy_Count   : Natural := 0;
   L_Ident_Count  : Natural := 0;
   Current_Config : Config_Type
     (Version         => Version,
      Policy_Count    => Max_Policy_Count,
      Local_Ids_Count => Max_Local_Identities_Count);

end Tkm.Config;
