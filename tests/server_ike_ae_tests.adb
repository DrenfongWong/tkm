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
with Tkmrpc.Contexts.ae;
with Tkmrpc.Servers.Ike;

package body Server_Ike_Ae_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_Ae_Reset
   is
      use type Results.Result_Type;

      Res : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Contexts.ae.create
        (Id              => 1,
         iag_id          => 2,
         dhag_id         => 3,
         creation_time   => 37,
         initiator       => 25,
         sk_ike_auth_loc => Types.Null_Key_Type,
         sk_ike_auth_rem => Types.Null_Key_Type,
         nonce_loc       => Types.Null_Nonce_Type,
         nonce_rem       => Types.Null_Nonce_Type);

      Servers.Ike.Ae_Reset
        (Result => Res,
         Ae_Id  => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Ae_Reset failed");

      Assert (Condition => Contexts.ae.Has_State
              (Id    => 1,
               State => Contexts.ae.clean),
              Message   => "AE context not 'clean'");
      Assert (Condition => Contexts.ae.Has_iag_id
              (Id     => 1,
               iag_id => Types.Iag_Id_Type'First),
              Message   => "Iag id not reset");
      Assert (Condition => Contexts.ae.Has_dhag_id
              (Id      => 1,
               dhag_id => Types.Dhag_Id_Type'First),
              Message   => "Dhag id not reset");
      Assert (Condition => Contexts.ae.Has_creation_time
              (Id            => 1,
               creation_time => Types.Rel_Time_Type'First),
              Message   => "Creation time not reset");
      Assert (Condition => Contexts.ae.Has_initiator
              (Id        => 1,
               initiator => Types.Init_Type'First),
              Message   => "Initiator not reset");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Ae_Reset (Result => Res,
                               Ae_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Ae_Reset;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server AE tests");
      T.Add_Test_Routine
        (Routine => Check_Ae_Reset'Access,
         Name    => "Check Ae_Reset");
   end Initialize;

end Server_Ike_Ae_Tests;
