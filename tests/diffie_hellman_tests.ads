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
