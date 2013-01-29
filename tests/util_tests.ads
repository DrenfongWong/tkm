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

with Ahven.Framework;

package Util_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Convert_Bytes_To_String;
   --  Convert bytes to string.

   procedure Convert_Byte_Sequence_To_Hex;
   --  Convert byte sequences to hex strings.

   procedure Convert_Bignum_To_Bytes;
   --  Convert GMP bignum to byte sequence.

   procedure Convert_Hex_To_Bytes;
   --  Convert hex strings to byte sequences.

   procedure Convert_U64_To_Bytes;
   --  Convert unsigned 64 to byte sequence.

   procedure Convert_String_To_Bytes;
   --  Convert string to byte sequence.

   procedure Convert_U32_To_Hex;
   --  Convert unsigned 32 to hex string.

   procedure Convert_U64_To_Hex;
   --  Convert unsigned 64 to hex string.

end Util_Tests;
