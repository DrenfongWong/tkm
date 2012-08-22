with Ahven.Framework;

--  HMAC tests, see RFC 4231 section 4
package Hmac_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Case1_Hmac_Sha512;
   --  HMAC Test Case 1.

   procedure Case2_Hmac_Sha512;
   --  HMAC Test Case 2.

   procedure Case3_Hmac_Sha512;
   --  HMAC Test Case 3.

   procedure Case4_Hmac_Sha512;
   --  HMAC Test Case 4.

   procedure Case5_Hmac_Sha512;
   --  HMAC Test Case 5.

   procedure Case6_Hmac_Sha512;
   --  HMAC Test Case 6

   procedure Case7_Hmac_Sha512;
   --  HMAC Test Case 7

end Hmac_Tests;
