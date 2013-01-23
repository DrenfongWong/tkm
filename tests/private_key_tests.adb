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

with X509.Keys;

with Tkm.Private_Key;

package body Private_Key_Tests
is

   use Ahven;

   -------------------------------------------------------------------------

   procedure Get_Key_Not_Initialized
   is
   begin
      declare
         Dummy : constant X509.Keys.RSA_Private_Key_Type
           := Tkm.Private_Key.Get;
         pragma Unreferenced (Dummy);
      begin
         Fail (Message => "Exception expected");
      end;

   exception
      when Tkm.Private_Key.Key_Uninitialized => null;
   end Get_Key_Not_Initialized;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Private key tests");
      T.Add_Test_Routine
        (Routine => Get_Key_Not_Initialized'Access,
         Name    => "Get uninitialized key");
   end Initialize;

end Private_Key_Tests;
