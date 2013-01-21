with Ahven.Framework;

package Identity_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure String_To_Identity;
   --  Verify string to identity conversion function.

   procedure Encode_Identity;
   --  Verify identity encoding.

end Identity_Tests;
