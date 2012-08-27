with Interfaces;

with GMP.Binding;

with Tkmrpc.Types;

package Tkm.Utils
is

   function To_String (Input : Tkmrpc.Types.Byte_Sequence) return String;
   --  Convert given byte sequence to string.

   function To_Hex_String (Input : Tkmrpc.Types.Byte_Sequence) return String;
   --  Return hex string represenation of byte sequence.

   function To_Bytes (Input : String) return Tkmrpc.Types.Byte_Sequence;
   --  Return byte sequence of hex string.

   procedure To_Bytes
     (Bignum :     GMP.Binding.Mpz_T;
      Bytes  : out Tkmrpc.Types.Byte_Sequence);
   --  Convert given GMP bignum to byte sequence. The given byte sequence must
   --  be big enough to hold the result or else Conversion_Error is raised. If
   --  the given byte sequence is bigger than needed, the result is prepended
   --  with zeros.

   function To_Bytes
     (Input : Interfaces.Unsigned_64)
      return Tkmrpc.Types.Byte_Sequence;
   --  Return byte sequence for given unsigned 64-bit number.

   Conversion_Error : exception;

end Tkm.Utils;
