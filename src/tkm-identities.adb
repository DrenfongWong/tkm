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

   ID_Payload_Hdr_Length : constant := 4;
   --  IKE ID payload header length in bytes, see RFC5996, section 3.5.

   function Is_Email (Id : Tkmrpc.Types.Identity_Type) return Boolean;
   --  Returns True if given id is an email address.

   -------------------------------------------------------------------------

   function Encode
     (Identity : Tkmrpc.Types.Identity_Type)
      return Tkmrpc.Types.Identity_Type
   is
      Ident : Tkmrpc.Types.Identity_Type
        := (Size => Identity.Size + ID_Payload_Hdr_Length,
            Data => (others => 0));
   begin
      if Is_Email (Id => Identity) then
         Ident.Data (Ident.Data'First) := 3;
      else
         Ident.Data (Ident.Data'First) := 2;
      end if;
      Ident.Data (Ident.Data'First + ID_Payload_Hdr_Length .. Ident.Size)
        := Identity.Data (Identity.Data'First .. Identity.Size);
      return Ident;
   end Encode;

   -------------------------------------------------------------------------

   function Is_Email (Id : Tkmrpc.Types.Identity_Type) return Boolean
   is
      use type Tkmrpc.Types.Byte;
   begin
      for I in Id.Data'First ..  Id.Size loop
         if Id.Data (I) = 16#40# then

            --  The current byte is a '@'

            return True;
         end if;
      end loop;

      return False;
   end Is_Email;

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
