with Ahven.Framework;

package Server_Ike_Tkm_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_Limits;
   --  Check TKM limits operation.

   procedure Check_Version;
   --  Check TKM version operation.

end Server_Ike_Tkm_Tests;
