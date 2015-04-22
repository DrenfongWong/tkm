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

with System.Assertions;

with Tkmrpc.Types;
with Tkmrpc.Contexts.dh;

package body Assertion_Tests
is

   use Ahven;

   -------------------------------------------------------------------------

   procedure Assertion_Policy
   is
      procedure Dummy (X : Integer)
      with
        Pre => X > 0;

      procedure Dummy (X : Integer)
      is
      begin
         null;
      end Dummy;
   begin
      Dummy (X => -1);
      Fail (Message => "Exception expected");

   exception
      when System.Assertions.Assert_Failure => null;
   end Assertion_Policy;

   -------------------------------------------------------------------------

   procedure Assertion_Policy_RPC
   is
   begin
      Tkmrpc.Contexts.dh.generate
        (Id        => 12,
         dh_key    => Tkmrpc.Types.Null_Dh_Key_Type,
         timestamp => 0);
      Fail (Message => "Exception expected");

   exception
      when System.Assertions.Assert_Failure => null;
   end Assertion_Policy_RPC;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Assertion policy tests");
      T.Add_Test_Routine
        (Routine => Assertion_Policy'Access,
         Name    => "Check assertion policy");
      T.Add_Test_Routine
        (Routine => Assertion_Policy_RPC'Access,
         Name    => "Check assertion policy (RPC)");
   end Initialize;

end Assertion_Tests;
