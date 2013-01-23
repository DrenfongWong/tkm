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

package Tkm.Digests
is

   Sha1_Digest_Info   : constant String
     := "3021300906052b0e03021a05000414";
   --  DER encoding T of the DigestInfo value for SHA-1.

   Sha256_Digest_Info : constant String
     := "3031300d060960864801650304020105000420";
   --  DER encoding T of the DigestInfo value for SHA-256.

end Tkm.Digests;
