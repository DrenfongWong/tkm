with Ahven.Framework;

package Server_Ike_Ae_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_Ae_Reset;
   --  Check authenticated endpoint reset.

end Server_Ike_Ae_Tests;
