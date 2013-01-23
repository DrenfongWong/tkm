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

with Tkmrpc.Types;

with Tkm.Identities;
with Tkm.Config.Test;

package body Identity_Tests is

   use Ahven;
   use Tkm;

   use type Tkmrpc.Types.Identity_Type;

   -------------------------------------------------------------------------

   procedure Encode_Identity
   is
      Encoded_Id : constant Tkmrpc.Types.Identity_Type
        := (Size => 24,
            Data =>
              (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#, 16#63#,
               16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#, 16#6E#, 16#67#,
               16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#, 16#6F#, 16#72#, 16#67#,
               others => 0));
   begin
      Assert
        (Condition => Identities.Encode (Identity => Tkm.Config.Test.Alice_Id)
         = Encoded_Id,
         Message   => "Encoded identity mismatch");
   end Encode_Identity;

   -------------------------------------------------------------------------

   procedure Identity_To_String
   is
   begin
      Assert (Condition => Identities.To_String
              (Identity => Tkm.Config.Test.Alice_Id)
              = "alice@strongswan.org",
              Message   => "Identity string mismatch");
   end Identity_To_String;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Identity tests");
      T.Add_Test_Routine
        (Routine => String_To_Identity'Access,
         Name    => "String to identity conversion");
      T.Add_Test_Routine
        (Routine => Encode_Identity'Access,
         Name    => "Encode identity");
      T.Add_Test_Routine
        (Routine => Identity_To_String'Access,
         Name    => "Identity to string conversion");
   end Initialize;

   -------------------------------------------------------------------------

   procedure String_To_Identity
   is
   begin
      Assert
        (Condition => Identities.To_Identity (Str => "alice@strongswan.org")
         = Tkm.Config.Test.Alice_Id,
         Message   => "Alice identity mismatch");
   end String_To_Identity;

end Identity_Tests;
