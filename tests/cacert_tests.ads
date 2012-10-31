with Ahven.Framework;

package Cacert_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Load_Certs;
   --  Load various certs.

   procedure Verify_Signature;
   --  Verify a certificate signature.

end Cacert_Tests;
