with Tkmrpc.Types;

with Tkm.Identities;
with Tkm.Config.Test;

package body Identity_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Identity tests");
      T.Add_Test_Routine
        (Routine => String_To_Identity'Access,
         Name    => "String to identity conversion");
   end Initialize;

   -------------------------------------------------------------------------

   procedure String_To_Identity
   is
      use type Tkmrpc.Types.Identity_Type;
   begin
      Assert
        (Condition => Identities.To_Identity (Str => "alice@strongswan.org")
         = Tkm.Config.Test.Alice_Id,
         Message   => "Alice identity mismatch");
   end String_To_Identity;

end Identity_Tests;
