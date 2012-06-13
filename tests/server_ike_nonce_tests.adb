with Interfaces;

with Tkmrpc.Results;
with Tkmrpc.Types;
with Tkmrpc.Servers.Ike;

with Tkm.Random;

package body Server_Ike_Nonce_Tests is

   use Ahven;
   use Tkmrpc;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Check_Nc_Create
   is
      use type Interfaces.Unsigned_32;
      use type Tkmrpc.Results.Result_Type;
      use type Tkmrpc.Types.Byte;

      Length : constant := 128;
      Nonce  : Types.Nonce_Type;
      Res    : Results.Result_Type;
   begin
      Random.Init;
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

      Random.Finalize;

   exception
      when others =>
         Random.Finalize;
         raise;
   end Check_Nc_Create;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Server IKE tests");
      T.Add_Test_Routine
        (Routine => Check_Nc_Create'Access,
         Name    => "Check Nc_Create");
   end Initialize;

end Server_Ike_Nonce_Tests;
