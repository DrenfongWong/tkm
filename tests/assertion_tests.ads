with Ahven.Framework;

package Assertion_Tests
is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Assertion_Policy;
   --  Assert correct assertion policy.

   procedure Assertion_Policy_RPC;
   --  Assert correct assertion policy of Tkmrpc project.

end Assertion_Tests;
