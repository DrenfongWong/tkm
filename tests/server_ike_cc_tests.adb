with Tkmrpc.Types;
with Tkmrpc.Results;
with Tkmrpc.Contexts.cc;
with Tkmrpc.Servers.Ike;

package body Server_Ike_Cc_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_Cc_Reset
   is
      use type Results.Result_Type;

      Res : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Contexts.cc.create
        (Id          => 1,
         authag_id   => 5,
         ri_id       => 2,
         certificate => Types.Null_Certificate_Type,
         not_before  => 25,
         not_after   => 67);

      Servers.Ike.Cc_Reset
        (Result => Res,
         Cc_Id  => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Cc_Reset failed");

      Assert (Condition => Contexts.cc.Has_State
              (Id    => 1,
               State => Contexts.cc.clean),
              Message   => "CC context not 'clean'");
      Assert (Condition => Contexts.cc.Has_authag_id
              (Id        => 1,
               authag_id => Types.Authag_Id_Type'First),
              Message   => "Authag id not reset");
      Assert (Condition => Contexts.cc.Has_ri_id
              (Id    => 1,
               ri_id => Types.Ri_Id_Type'First),
              Message   => "Ri id not reset");
      Assert (Condition => Contexts.cc.Has_certificate
              (Id          => 1,
               certificate => Types.Null_Certificate_Type),
              Message   => "Certificate not reset");
      Assert (Condition => Contexts.cc.Has_not_before
              (Id         => 1,
               not_before => Types.Abs_Time_Type'First),
              Message   => "not before not reset");
      Assert (Condition => Contexts.cc.Has_not_after
              (Id        => 1,
               not_after => Types.Abs_Time_Type'First),
              Message   => "not after not reset");

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Cc_Reset (Result => Res,
                               Cc_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Cc_Reset;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server CC tests");
      T.Add_Test_Routine
        (Routine => Check_Cc_Reset'Access,
         Name    => "Check Cc_Reset");
   end Initialize;

end Server_Ike_Cc_Tests;
