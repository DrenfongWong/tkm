with Ada.Exceptions;

with Tkmrpc.Transport.Servers;
with Tkmrpc.Servers.Ike;

with Tkm.Logger;
with Tkm.Version;
with Tkm.Dispatchers;
with Tkm.Xfrm;
with Tkm.Config;

procedure Key_Manager
is
   use Tkmrpc;

   package L renames Tkm.Logger;

   IKE_Socket : constant String := "/tmp/tkm.rpc.ike";
   RPC_Server : Transport.Servers.Server_Type;
begin
   L.Use_File;
   L.Log (Message => "Trusted Key Manager (TKM) starting ("
          & Tkm.Version.Version_String & ")");

   --  Install test policies

   Tkm.Xfrm.Flush;
   Tkm.Xfrm.Add_Policy (Source      => Tkm.Config.Local_Addr,
                        Destination => Tkm.Config.Peer_Addr);
   Tkm.Xfrm.Add_Policy (Source      => Tkm.Config.Peer_Addr,
                        Destination => Tkm.Config.Local_Addr);
   L.Log (Message => "XFRM test policies installed");

   Servers.Ike.Init;
   Transport.Servers.Listen
     (Server  => RPC_Server,
      Address => IKE_Socket,
      Process => Tkm.Dispatchers.Dispatch_Ike_Request'Access);

exception
   when E : others =>
      L.Log (Level   => L.Error,
             Message => "Terminating due to error");
      L.Log (Level   => L.Error,
             Message => Ada.Exceptions.Exception_Information (X => E));
      L.Stop;
end Key_Manager;
