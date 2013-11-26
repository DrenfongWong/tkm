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

with Interfaces;

with Tkmrpc.Results;
with Tkmrpc.Types;
with Tkmrpc.Servers.Ike;

package body Server_Ike_DH_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_DH_Operations
   is
      use type Interfaces.Unsigned_32;
      use type Tkmrpc.Results.Result_Type;
      use type Tkmrpc.Types.Byte_Sequence;

      Id  : constant := 11;
      Res : Results.Result_Type;
      Pub : Types.Dh_Pubvalue_Type;

      Null_Bytes : constant Types.Byte_Sequence (1 .. 512) := (others => 0);
   begin
      Servers.Ike.Init;
      Servers.Ike.Dh_Create
        (Result   => Res,
         Dh_Id    => Id,
         Dha_Id   => 2,
         Pubvalue => Pub);
      Assert (Condition => Res = Results.Ok,
              Message   => "Dh_Create failed");
      Assert (Condition => Pub.Size = 512,
              Message   => "Public value size mismatch");
      Assert (Condition => Pub.Data /= Null_Bytes,
              Message   => "Public data is nil");

      --  Use own pubvalue for other side too.

      Servers.Ike.Dh_Generate_Key (Result   => Res,
                                   Dh_Id    => Id,
                                   Pubvalue => Pub);
      Assert (Condition => Res = Results.Ok,
              Message   => "Dh_Generate_Key failed");

      Servers.Ike.Dh_Reset (Result => Res,
                            Dh_Id  => Id);
      Assert (Condition => Res = Results.Ok,
              Message   => "Dh_Reset failed");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Dh_Reset (Result => Res,
                               Dh_Id  => Id);
         Servers.Ike.Finalize;
         raise;
   end Check_DH_Operations;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server Diffie-Hellman tests");
      T.Add_Test_Routine
        (Routine => Check_DH_Operations'Access,
         Name    => "Check DH operations");
   end Initialize;

end Server_Ike_DH_Tests;
