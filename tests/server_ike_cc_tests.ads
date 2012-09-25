with Ahven.Framework;

package Server_Ike_Cc_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_Cc_Reset;
   --  Check certificate context reset.

end Server_Ike_Cc_Tests;
