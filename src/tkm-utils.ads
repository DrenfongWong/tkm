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

with X509;

with Interfaces;

with GMP.Binding;

with Tkmrpc.Types;

package Tkm.Utils
is

   function To_String (Input : Tkmrpc.Types.Byte_Sequence) return String;
   --  Convert given byte sequence to string.

   function To_Hex_String (Input : Tkmrpc.Types.Byte_Sequence) return String;
   --  Return hex string represenation of byte sequence.

   function Hex_To_Bytes (Input : String) return Tkmrpc.Types.Byte_Sequence;
   --  Return byte sequence of hex string.

   function To_Bytes (Input : String) return Tkmrpc.Types.Byte_Sequence;
   --  Return byte sequence of given string.

   procedure To_Bytes
     (Bignum :     GMP.Binding.Mpz_T;
      Bytes  : out Tkmrpc.Types.Byte_Sequence);
   --  Convert given GMP bignum to byte sequence. The given byte sequence must
   --  be big enough to hold the result or else Conversion_Error is raised. If
   --  the given byte sequence is bigger than needed, the result is prepended
   --  with zeros.

   function To_Bytes
     (Bignum : GMP.Binding.Mpz_T)
      return Tkmrpc.Types.Byte_Sequence;
   --  Convert given GMP bignum to byte sequence.

   function To_Bytes
     (Input : Interfaces.Unsigned_64)
      return Tkmrpc.Types.Byte_Sequence;
   --  Return byte sequence for given unsigned 64-bit number.

   function To_X509_Bytes
     (Item : Tkmrpc.Types.Byte_Sequence)
      return X509.Byte_Array;
   --  Convert given byte sequence to X509 byte array.

   function To_Sequence
     (Item : X509.Byte_Array)
      return Tkmrpc.Types.Byte_Sequence;
   --  Convert given X509 byte array to byte sequence.

   function To_Hex_String (Input : Interfaces.Unsigned_32) return String;
   --  Return hex string represenation of unsigned 32-bit number.

   function To_Hex_String (Input : Interfaces.Unsigned_64) return String;
   --  Return hex string represenation of unsigned 64-bit number.

   Conversion_Error : exception;

end Tkm.Utils;
