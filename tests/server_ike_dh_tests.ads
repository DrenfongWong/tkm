with Ahven.Framework;

package Server_Ike_DH_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_DH_Operations;
   --  Check Diffie-Hellman operations.

end Server_Ike_DH_Tests;
