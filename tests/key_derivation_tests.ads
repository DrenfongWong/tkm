with Ahven.Framework;

package Key_Derivation_Tests
is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Derive_Child_Keys;
   --  Verify child key derivation.

end Key_Derivation_Tests;
