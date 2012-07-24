with Ahven.Framework;

package Util_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Convert_Byte_Sequence_To_Hex;
   --  Convert byte sequences to hex strings.

   procedure Convert_Bignum_To_Bytes;
   --  Convert GMP bignum to byte sequence.

end Util_Tests;
