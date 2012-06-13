with Tkmrpc.Transport.Servers;
with Tkmrpc.Dispatchers.Ike;
with Tkmrpc.Servers.Ike;

with Tkm.Logger;
with Tkm.Version;

procedure Key_Manager
is
   use Tkmrpc;

   package L renames Tkm.Logger;

   IKE_Socket : constant String := "/tmp/tkm.rpc.ike";
   RPC_Server : Transport.Servers.Server_Type;
begin
   L.Use_Stdout;
   L.Log (Message => "Trusted Key Manager (TKM) starting ("
          & Tkm.Version.Version_String & ")");

   Servers.Ike.Init;
   Transport.Servers.Listen (Server  => RPC_Server,
                             Address => IKE_Socket,
                             Process => Dispatchers.Ike.Dispatch'Access);
end Key_Manager;
