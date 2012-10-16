with X509.Keys;

with Tkm.Private_Key;

package body Private_Key_Tests
is

   use Ahven;

   -------------------------------------------------------------------------

   procedure Get_Key_Not_Initialized
   is
   begin
      declare
         Dummy : constant X509.Keys.RSA_Private_Key_Type
           := Tkm.Private_Key.Get;
         pragma Unreferenced (Dummy);
      begin
         Fail (Message => "Exception expected");
      end;

   exception
      when Tkm.Private_Key.Key_Uninitialized => null;
   end Get_Key_Not_Initialized;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Private key tests");
      T.Add_Test_Routine
        (Routine => Get_Key_Not_Initialized'Access,
         Name    => "Get uninitialized key");
   end Initialize;

end Private_Key_Tests;
