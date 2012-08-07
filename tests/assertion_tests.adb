with System.Assertions;

with Tkm;

package body Assertion_Tests
is

   use Ahven;

   -------------------------------------------------------------------------

   procedure Assertion_Policy
   is
      procedure Dummy (X : Integer) is null
      with
        Pre => X > 0;

   begin
      Dummy (X => -1);
      Fail (Message => "Exception expected");

   exception
      when System.Assertions.Assert_Failure => null;
   end Assertion_Policy;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Assertion policy tests");
      T.Add_Test_Routine
        (Routine => Assertion_Policy'Access,
         Name    => "Check assertion policy");
   end Initialize;

end Assertion_Tests;
