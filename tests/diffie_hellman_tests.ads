with Ahven.Framework;

package Diffie_Hellman_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Compute_Xa_Ya_Zz;
   --  Verify DH xa, ya and zz computation.

   procedure Compute_Xa_Ya_Zz_Modp_3072;
   --  Verify DH xa, ya and zz computation (MODP-3072).

   procedure Invalid_Yb;
   --  Verify exception handling for invalid other public values.

   procedure Unsupported_DH_Group;
   --  Verify exception handling for unsupported DH group.

   procedure Get_Group_Size;
   --  Verify DH group sizes.

end Diffie_Hellman_Tests;
