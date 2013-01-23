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

with Tkm.Logger;

package body Tkm.Private_Key
is

   package L renames Tkm.Logger;

   Key : X509.Keys.RSA_Private_Key_Type;

   -------------------------------------------------------------------------

   function Get return X509.Keys.RSA_Private_Key_Type
   is
      use type X509.Keys.RSA_Private_Key_Type;
   begin
      if Key = X509.Keys.Null_Private_Key then
         raise Key_Uninitialized with "Private key not initialized";
      end if;

      return Key;
   end Get;

   -------------------------------------------------------------------------

   procedure Load (Path : String)
   is
   begin
      L.Log (Message => "Loading RSA private key '" & Path & "'");
      X509.Keys.Load (Filename => Path,
                      Key      => Key);
      L.Log (Message => "RSA private key '" & Path & "' loaded, key size"
             & X509.Keys.Get_Size (Key => Key)'Img & " bits");
   end Load;

end Tkm.Private_Key;
