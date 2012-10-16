with Ahven.Framework;

package Private_Key_Tests
is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Get_Key_Not_Initialized;
   --  Try to get an uninitialized key.

end Private_Key_Tests;
