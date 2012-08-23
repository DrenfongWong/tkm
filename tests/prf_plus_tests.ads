with Ahven.Framework;

package Prf_Plus_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Verify_Prf_Plus_Hmac_Sha512;
   --  Verify HMAC-SHA512 PRF+.

   procedure Seed_Exceeds_Max;
   --  Verify error behavior for invalid seed size.

end Prf_Plus_Tests;
