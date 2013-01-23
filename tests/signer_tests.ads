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

--  RSA PKCS#1 v1.5 Signature tests, see file doc/pkcs1v15sign-vectors.txt and
--  RFC 3447, section 8.2.
package Signer_Tests
is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Rsa_Pkcs1_v1_5_Example1;
   --  PKCS#1 v1.5 signature test  1 ( 1.1 -  1.4).

   procedure Rsa_Pkcs1_v1_5_Example11;
   --  PKCS#1 v1.5 signature test 11 (11.1 - 11.4).

   procedure Rsa_Pkcs1_v1_5_Example15;
   --  PKCS#1 v1.5 signature test 15 (15.1 - 15.4).

   procedure Rsa_Pkcs1_Modulus_Too_Short;
   --  PKCS#1 modulus too short test.

   procedure Rsa_Pkcs1_Signer_Not_Initialized;
   --  PKCS#1 signer not initialized test.

   procedure Rsa_Pkcs1_Verify_Signature;
   --  PKCS#1 verify signature test.

   procedure Rsa_Pkcs1_Verifier_Not_Initialized;
   --  PKCS#1 verifier not initialized test.

end Signer_Tests;
