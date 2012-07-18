with Ahven.Framework;

package Util_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Convert_Byte_Sequence_To_Hex;
   --  Convert byte sequences to hex strings.

end Util_Tests;
