with Tkmrpc.Types;

with Tkm.Identities;
with Tkm.Config.Test;

package body Identity_Tests is

   use Ahven;
   use Tkm;

   use type Tkmrpc.Types.Identity_Type;

   -------------------------------------------------------------------------

   procedure Encode_Identity
   is
      Encoded_Id : constant Tkmrpc.Types.Identity_Type
        := (Size => 24,
            Data =>
              (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#, 16#63#,
               16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#, 16#6E#, 16#67#,
               16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#, 16#6F#, 16#72#, 16#67#,
               others => 0));
   begin
      Assert
        (Condition => Identities.Encode (Identity => Tkm.Config.Test.Alice_Id)
         = Encoded_Id,
         Message   => "Encoded identity mismatch");
   end Encode_Identity;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Identity tests");
      T.Add_Test_Routine
        (Routine => String_To_Identity'Access,
         Name    => "String to identity conversion");
      T.Add_Test_Routine
        (Routine => Encode_Identity'Access,
         Name    => "Encode identity");
   end Initialize;

   -------------------------------------------------------------------------

   procedure String_To_Identity
   is
   begin
      Assert
        (Condition => Identities.To_Identity (Str => "alice@strongswan.org")
         = Tkm.Config.Test.Alice_Id,
         Message   => "Alice identity mismatch");
   end String_To_Identity;

end Identity_Tests;
