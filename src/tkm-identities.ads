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

package Tkm.Identities
is

   type Local_Identity_Type is record
      Id   : Tkmrpc.Types.Li_Id_Type;
      Name : Tkmrpc.Types.Identity_Type;
   end record;
   --  Identity type connects identity id with a name.

   Null_Local_Identity : constant Local_Identity_Type;

   type Local_Identities_Type is array (Positive range <>)
     of Local_Identity_Type;

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type;
   --  Create identity type from given string.

   function To_String (Identity : Tkmrpc.Types.Identity_Type) return String;
   --  Return string representation of given identity.

   function Encode
     (Identity : Tkmrpc.Types.Identity_Type)
      return Tkmrpc.Types.Identity_Type;
   --  Encode given identity by prepending IKE ID payload header.

private

   Null_Local_Identity : constant Local_Identity_Type
     := (Id => Tkmrpc.Types.Li_Id_Type'First,
         Name => Tkmrpc.Types.Null_Identity_Type);

end Tkm.Identities;
