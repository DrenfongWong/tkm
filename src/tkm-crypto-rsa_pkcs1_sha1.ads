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

with GNAT.SHA1;

with Tkm.Digests;
with Tkm.Crypto.Rsa_Pkcs1;

pragma Elaborate_All (Tkm.Crypto.Rsa_Pkcs1);

package Tkm.Crypto.Rsa_Pkcs1_Sha1 is
  new Tkm.Crypto.Rsa_Pkcs1
    (Hash_Ctx_Type => GNAT.SHA1.Context,
     Initial_Ctx   => GNAT.SHA1.Initial_Context,
     Digest_Info   => Digests.Sha1_Digest_Info,
     Update        => GNAT.SHA1.Update,
     Digest        => GNAT.SHA1.Digest);
