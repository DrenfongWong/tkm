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

with Ada.Exceptions;
with Ada.Command_Line;
with Ada.Strings.Unbounded;

with GNAT.Command_Line;

with Anet.Sockets.Unix;
with Anet.Receivers.Stream;

with Tkmrpc.Servers.Ike;
with Tkmrpc.Dispatchers.Ike;
with Tkmrpc.Process_Stream;

with Tkm.Logger;
with Tkm.Version;
with Tkm.Xfrm;
with Tkm.Config;
with Tkm.Callbacks;
with Tkm.Ca_Cert;
with Tkm.Private_Key;
with Tkm.Termination;

procedure Tkm_Keymanager
is

   use Ada.Strings.Unbounded;
   use Tkmrpc;

   package L renames Tkm.Logger;

   package Unix_TCP_Receiver is new Anet.Receivers.Stream
     (Socket_Type => Anet.Sockets.Unix.TCP_Socket_Type);

   procedure Dispatch is new Tkmrpc.Process_Stream
     (Dispatch          => Tkmrpc.Dispatchers.Ike.Dispatch,
      Exception_Handler => L.Log);

   procedure Print_Usage (Msg : String);
   --  Print usage information, set exit status to failure and stop logger.

   procedure Print_Usage (Msg : String)
   is
      use Ada.Command_Line;
   begin
      L.Log (Message => Msg);
      L.Log (Message => "Usage: " & Command_Name & " -c <config> -k <key> "
             & "-r <rootcert>");
      L.Log (Message => "  -c configuration file");
      L.Log (Message => "  -k RSA private key in DER format");
      L.Log (Message => "  -r Root CA certificate in DER format");
      L.Stop;
      Set_Exit_Status (Code => Failure);
   end Print_Usage;

   Private_Key, Ca_Cert, Cfg_File : Unbounded_String;

   IKE_Socket : constant String := "/tmp/tkm.rpc.ike";
   Sock       : aliased Anet.Sockets.Unix.TCP_Socket_Type;
   Receiver   : Unix_TCP_Receiver.Receiver_Type (S => Sock'Access);
begin
   L.Use_File;
   L.Log (Message => "Trusted Key Manager (TKM) starting ("
          & Tkm.Version.Version_String & ")");

   begin
      loop
         case GNAT.Command_Line.Getopt ("c: k: r:") is
            when ASCII.NUL => exit;
            when 'c'       =>
               Cfg_File := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 'k'       =>
               Private_Key := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 'r'       =>
               Ca_Cert := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when others    =>
               raise Program_Error;
         end case;
      end loop;

   exception
      when GNAT.Command_Line.Invalid_Switch =>
         Print_Usage (Msg => "Invalid switch -"
                      & GNAT.Command_Line.Full_Switch);
         return;
      when GNAT.Command_Line.Invalid_Parameter =>
         Print_Usage (Msg => "No parameter for -"
                      & GNAT.Command_Line.Full_Switch);
         return;
   end;

   if Cfg_File = Null_Unbounded_String then
      Print_Usage (Msg => "No configuration file specified");
      return;
   end if;
   if Private_Key = Null_Unbounded_String then
      Print_Usage (Msg => "No RSA private key specified");
      return;
   end if;
   if Ca_Cert = Null_Unbounded_String then
      Print_Usage (Msg => "No root CA certificate specified");
      return;
   end if;

   --  Load configuration

   Tkm.Config.Load (Filename => To_String (Cfg_File));

   --  Load CA certificate

   Tkm.Ca_Cert.Load (Path => To_String (Ca_Cert));

   --  Load RSA private key

   Tkm.Private_Key.Load (Path => To_String (Private_Key));

   --  Install configured policies

   Tkm.Xfrm.Init;
   Tkm.Xfrm.Flush;
   Tkm.Config.Iterate (Process => Tkm.Xfrm.Add_Policy'Access);

   Sock.Init;
   Sock.Bind (Path => Anet.Sockets.Unix.Path_Type (IKE_Socket));

   Servers.Ike.Init;

   Receiver.Register_Error_Handler
     (Callback => Tkm.Callbacks.Receiver_Error'Access);
   Receiver.Listen (Callback => Dispatch'Access);

   Ada.Command_Line.Set_Exit_Status (Code => Tkm.Termination.Wait);
   Receiver.Stop;
   Tkm.Xfrm.Flush;
   L.Stop;

exception
   when E : others =>
      L.Log (Level   => L.Error,
             Message => "Terminating due to error");
      L.Log (Level   => L.Error,
             Message => Ada.Exceptions.Exception_Information (X => E));
      L.Stop;
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
end Tkm_Keymanager;
