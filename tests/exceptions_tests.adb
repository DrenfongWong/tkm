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
with Tkmrpc.Results;

with Tkm.Exceptions;
with Tkm.Servers.Ike.DH;
with Tkm.Crypto.Rsa_Pkcs1_Sha1;

package body Exceptions_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Aborted_Mapping
   is
      use type Tkmrpc.Results.Result_Type;

      Res : Tkmrpc.Results.Result_Type := Tkmrpc.Results.Math_Error;
   begin
      begin
         raise Constraint_Error;

      exception
         when E : others =>
            Exceptions.Handle_Exception (Ex     => E,
                                         Result => Res);
      end;
      Assert (Condition => Res = Tkmrpc.Results.Aborted,
              Message   => "Incorrect mapping of 'Aborted'");
   end Aborted_Mapping;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Exceptions tests");
      T.Add_Test_Routine
        (Routine => Invalid_State_Mapping'Access,
         Name    => "Invalid state mapping");
      T.Add_Test_Routine
        (Routine => Sign_Failure_Mapping'Access,
         Name    => "Sign failure mapping");
      T.Add_Test_Routine
        (Routine => Aborted_Mapping'Access,
         Name    => "Aborted mapping");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Invalid_State_Mapping
   is
      use type Tkmrpc.Results.Result_Type;

      Res : Tkmrpc.Results.Result_Type := Tkmrpc.Results.Math_Error;
   begin
      begin
         Tkm.Servers.Ike.DH.Generate_Key
           (Id       => 42,
            Pubvalue => Tkmrpc.Types.Null_Dh_Pubvalue_Type);

      exception
         when E : others =>
            Exceptions.Handle_Exception (Ex     => E,
                                         Result => Res);
      end;
      Assert (Condition => Res = Tkmrpc.Results.Invalid_State,
              Message   => "Incorrect mapping of 'Invalid_State'");
   end Invalid_State_Mapping;

   -------------------------------------------------------------------------

   procedure Sign_Failure_Mapping
   is
      use type Tkmrpc.Results.Result_Type;

      Res : Tkmrpc.Results.Result_Type := Tkmrpc.Results.Math_Error;
   begin
      begin
         declare
            pragma Warnings (Off, "variable ""C"" is read but never assigned");
            C : Crypto.Rsa_Pkcs1_Sha1.Signer_Type;
            pragma Warnings (On, "variable ""C"" is read but never assigned");
            Dummy : Tkmrpc.Types.Byte_Sequence
              := Crypto.Rsa_Pkcs1_Sha1.Generate
                (Ctx  => C,
                 Data => Tkmrpc.Types.Identity_Type_Data_Type'(others => 0));
            pragma Unreferenced (Dummy);
         begin
            null;
         end;

      exception
         when E : others =>
            Exceptions.Handle_Exception (Ex     => E,
                                         Result => Res);
      end;
      Assert (Condition => Res = Tkmrpc.Results.Sign_Failure,
              Message   => "Incorrect mapping of 'Sign_Failure'");
   end Sign_Failure_Mapping;

end Exceptions_Tests;
