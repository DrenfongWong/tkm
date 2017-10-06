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

with Tkmrpc.Results;
with Tkmrpc.Types;
with Tkmrpc.Servers.Ike;

package body Server_Ike_Nonce_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_Nc_Create
   is
      use type Tkmrpc.Results.Result_Type;
      use type Tkmrpc.Types.Byte;

      Length : constant := 128;
      Nonce  : Types.Nonce_Type;
      Res    : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Servers.Ike.Nc_Create (Result       => Res,
                             Nc_Id        => 1,
                             Nonce_Length => Length,
                             Nonce        => Nonce);
      Assert (Condition => Res = Results.Ok,
              Message   => "Call failed");
      Assert (Condition => Nonce.Size = Length,
              Message   => "Nonce size mismatch");
      for B in Length + 1 .. Nonce.Data'Last loop
         Assert (Condition => Nonce.Data (B) = 0,
                 Message   => "Byte" & B'Img & " not zero");
      end loop;

      Servers.Ike.Nc_Reset (Result => Res,
                            Nc_Id  => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Nc_Reset failed");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Nc_Reset (Result => Res,
                               Nc_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Nc_Create;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server nonce tests");
      T.Add_Test_Routine
        (Routine => Check_Nc_Create'Access,
         Name    => "Check Nc_Create");
   end Initialize;

end Server_Ike_Nonce_Tests;
