with Ada.Exceptions;

with Anet.Types;
with Anet.Sockets.Unix;
with Anet.Receivers.Stream;

with Tkmrpc.Servers.Ike;
with Tkmrpc.Dispatchers.Ike;
with Tkmrpc.Process_Stream;

with Tkm.Logger;
with Tkm.Version;
with Tkm.Xfrm;
with Tkm.Config;

procedure Key_Manager
is

   use Tkmrpc;

   package L renames Tkm.Logger;

   package Unix_TCP_Receiver is new Anet.Receivers.Stream
     (Socket_Type => Anet.Sockets.Unix.TCP_Socket_Type);

   procedure Dispatch is new Tkmrpc.Process_Stream
     (Dispatch          => Tkmrpc.Dispatchers.Ike.Dispatch,
      Exception_Handler => L.Log);

   IKE_Socket : constant String := "/tmp/tkm.rpc.ike";
   Sock       : aliased Anet.Sockets.Unix.TCP_Socket_Type;
   Receiver   : Unix_TCP_Receiver.Receiver_Type (S => Sock'Access);
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

   Sock.Init;
   Sock.Bind (Path => Anet.Types.Unix_Path_Type (IKE_Socket));

   Servers.Ike.Init;

   Receiver.Listen (Callback => Dispatch'Access);

exception
   when E : others =>
      L.Log (Level   => L.Error,
             Message => "Terminating due to error");
      L.Log (Level   => L.Error,
             Message => Ada.Exceptions.Exception_Information (X => E));
      L.Stop;
end Key_Manager;
