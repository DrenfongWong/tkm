--
--  Copyright (C) 2013  Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2013  Adrian-Ken Rueegsegger <ken@codelabs.ch>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

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
