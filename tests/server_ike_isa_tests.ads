with Ahven.Framework;

package Server_Ike_Isa_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Check_Isa_Create;
   --  Check IKE SA creation.

   procedure Check_Isa_Create_Child;
   --  Check IKE SA child creation (rekey).

   procedure Check_Isa_Skip_Create_First;
   --  Check IKE SA skip first child creation.

end Server_Ike_Isa_Tests;
