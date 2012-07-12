with Ahven.Framework;

package Locked_Mem_Tests
is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Lock_And_Wipe;
   --  Test memory locking and scrubbing mechanism.

end Locked_Mem_Tests;
