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

with X509.Keys;

package Tkm.Private_Key
is

   procedure Load (Path : String);
   --  Load RSA private key from file given by path.

   function Get return X509.Keys.RSA_Private_Key_Type;
   --  Return previously loaded RSA private key. Raises a Key_Uninitialized
   --  exception if no key has been loaded.

   Key_Uninitialized : exception;

end Tkm.Private_Key;
