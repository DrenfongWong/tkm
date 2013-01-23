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

package body Tkm.Identities
is

   ID_Payload_Hdr : constant Tkmrpc.Types.Byte_Sequence := (3, 0, 0, 0);
   --  IKE ID payload header, see RFC 5996, section 3.5.

   -------------------------------------------------------------------------

   function Encode
     (Identity : Tkmrpc.Types.Identity_Type)
      return Tkmrpc.Types.Identity_Type
   is
      Ident : Tkmrpc.Types.Identity_Type
        := (Size => Identity.Size + ID_Payload_Hdr'Length,
            Data => (others => 0));
   begin
      Ident.Data (Ident.Data'First .. ID_Payload_Hdr'Length) := ID_Payload_Hdr;
      Ident.Data (Ident.Data'First + ID_Payload_Hdr'Length .. Ident.Size)
        := Identity.Data (Identity.Data'First .. Identity.Size);
      return Ident;
   end Encode;

   -------------------------------------------------------------------------

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type
   is
      Identity : Tkmrpc.Types.Identity_Type
        := (Size => Str'Length,
            Data => (others => 0));
   begin
      for I in Str'Range loop
         Identity.Data (I) := Character'Pos (Str (I));
      end loop;

      return Identity;
   end To_Identity;

   -------------------------------------------------------------------------

   function To_String (Identity : Tkmrpc.Types.Identity_Type) return String
   is
      Id_Str : String (1 .. Identity.Size);
   begin
      for I in Id_Str'Range loop
         Id_Str (I) := Character'Val (Identity.Data (I));
      end loop;

      return Id_Str;
   end To_String;

end Tkm.Identities;
