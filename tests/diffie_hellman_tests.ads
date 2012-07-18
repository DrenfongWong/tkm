with Ahven.Framework;

package Diffie_Hellman_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Compute_Xa_Ya_Zz;
   --  Verify DH xa, ya and zz computation.

end Diffie_Hellman_Tests;
