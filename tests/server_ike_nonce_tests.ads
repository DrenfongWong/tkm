with Ahven.Framework;

package Server_Ike_Nonce_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_Nc_Create;
   --  Check Nc_Create operation.

end Server_Ike_Nonce_Tests;
