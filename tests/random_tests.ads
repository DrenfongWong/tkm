with Ahven.Framework;

package Random_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Get_Random_Bytes;
   --  Verify random bytes getter function.

end Random_Tests;
