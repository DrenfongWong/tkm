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
with Tkmrpc.Constants;
with Tkmrpc.Servers.Ike;
with Tkmrpc.Contexts.nc;
with Tkmrpc.Contexts.dh;

package body Server_Ike_Tkm_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_Limits
   is
      use type Types.Active_Requests_Type;
      use type Tkmrpc.Results.Result_Type;
      use type Tkmrpc.Types.Ae_Id_Type;
      use type Tkmrpc.Types.Cc_Id_Type;
      use type Tkmrpc.Types.Dh_Id_Type;
      use type Tkmrpc.Types.Nc_Id_Type;
      use type Tkmrpc.Types.Isa_Id_Type;
      use type Tkmrpc.Types.Esa_Id_Type;

      Res      : Results.Result_Type;
      Max_Reqs : Types.Active_Requests_Type;
      Nc_Ctxs  : Types.Nc_Id_Type;
      Dh_Ctxs  : Types.Dh_Id_Type;
      Cc_Ctxs  : Types.Cc_Id_Type;
      Ae_Ctxs  : Types.Ae_Id_Type;
      Isa_Ctxs : Types.Isa_Id_Type;
      Esa_Ctxs : Types.Esa_Id_Type;
   begin
      Servers.Ike.Init;
      Servers.Ike.Tkm_Limits (Result              => Res,
                              Max_Active_Requests => Max_Reqs,
                              Nc_Contexts         => Nc_Ctxs,
                              Dh_Contexts         => Dh_Ctxs,
                              Cc_Contexts         => Cc_Ctxs,
                              Ae_Contexts         => Ae_Ctxs,
                              Isa_Contexts        => Isa_Ctxs,
                              Esa_Contexts        => Esa_Ctxs);

      Assert (Condition => Res = Results.Ok,
              Message   => "TKM limits failed");
      Assert (Condition => Max_Reqs = 1,
              Message   => "Max requests limit mismatch");
      Assert (Condition => Nc_Ctxs = Types.Nc_Id_Type'Last,
              Message   => "Nc contexts limit mismatch");
      Assert (Condition => Dh_Ctxs = Types.Dh_Id_Type'Last,
              Message   => "Dh contexts limit mismatch");
      Assert (Condition => Cc_Ctxs = Types.Cc_Id_Type'Last,
              Message   => "Cc contexts limit mismatch");
      Assert (Condition => Ae_Ctxs = Types.Ae_Id_Type'Last,
              Message   => "Ae contexts limit mismatch");
      Assert (Condition => Isa_Ctxs = Types.Isa_Id_Type'Last,
              Message   => "Isa contexts limit mismatch");
      Assert (Condition => Esa_Ctxs = Types.Esa_Id_Type'Last,
              Message   => "Esa contexts limit mismatch");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Finalize;
         raise;
   end Check_Limits;

   -------------------------------------------------------------------------

   procedure Check_Reset
   is
      use type Tkmrpc.Results.Result_Type;
      use type Tkmrpc.Contexts.nc.nc_State_Type;
      use type Tkmrpc.Contexts.dh.dh_State_Type;

      Res : Results.Result_Type;
   begin
      Contexts.nc.create
        (Id    => 1,
         nonce => Types.Null_Nonce_Type);
      Contexts.dh.create
        (Id       => 1,
         dha_id   => 1,
         secvalue => Types.Null_Dh_Priv_Type);

      Servers.Ike.Init;
      Servers.Ike.Tkm_Reset (Result => Res);

      Assert (Condition => Res = Results.Ok,
              Message   => "TKM reset failed");
      Assert (Condition => Contexts.nc.Get_State
              (Id => 1) = Contexts.nc.clean,
              Message   => "Nc context not reset");
      Assert (Condition => Contexts.dh.Get_State
              (Id => 1) = Contexts.dh.clean,
              Message   => "Dh context not reset");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Finalize;
         raise;
   end Check_Reset;

   -------------------------------------------------------------------------

   procedure Check_Version
   is
      use type Types.Version_Type;
      use type Tkmrpc.Results.Result_Type;

      Res : Results.Result_Type;
      Ver : Types.Version_Type;
   begin
      Servers.Ike.Init;
      Servers.Ike.Tkm_Version (Result  => Res,
                               Version => Ver);

      Assert (Condition => Res = Results.Ok,
              Message   => "TKM version failed");
      Assert (Condition => Ver = Constants.Ike_Version,
              Message   => "IKE version mismatch");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Finalize;
         raise;
   end Check_Version;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server TKM tests");
      T.Add_Test_Routine
        (Routine => Check_Limits'Access,
         Name    => "Check Tkm_Limits");
      T.Add_Test_Routine
        (Routine => Check_Version'Access,
         Name    => "Check Tkm_Version");
      T.Add_Test_Routine
        (Routine => Check_Reset'Access,
         Name    => "Check Tkm_Reset");
   end Initialize;

end Server_Ike_Tkm_Tests;
