with System.Assertions;

with Tkmrpc.Types;
with Tkmrpc.Contexts.dh;

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

   procedure Assertion_Policy_RPC
   is
   begin
      Tkmrpc.Contexts.dh.generate
        (Id        => 12,
         dh_key    => Tkmrpc.Types.Null_Dh_Key_Type,
         timestamp => 0);
      Fail (Message => "Exception expected");

   exception
      when System.Assertions.Assert_Failure => null;
   end Assertion_Policy_RPC;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Assertion policy tests");
      T.Add_Test_Routine
        (Routine => Assertion_Policy'Access,
         Name    => "Check assertion policy");
      T.Add_Test_Routine
        (Routine => Assertion_Policy_RPC'Access,
         Name    => "Check assertion policy (RPC)");
   end Initialize;

end Assertion_Tests;
