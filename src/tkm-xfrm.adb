with GNAT.OS_Lib;

with Tkm.Logger;
with Tkm.Utils;

package body Tkm.Xfrm
is

   package L renames Tkm.Logger;

   procedure System (Command : String);
   --  Execute command.

   -------------------------------------------------------------------------

   procedure Add_Policy
     (Source      : String;
      Destination : String)
   is
   begin
      System (Command => "/bin/ip xfrm policy add dir out"
              & " src " & Source
              & " dst " & Destination
              & " tmpl src 0.0.0.0 dst 0.0.0.0"
              & " proto esp");
   end Add_Policy;

   -------------------------------------------------------------------------

   procedure Add_State
     (Source      : String;
      Destination : String;
      SPI         : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key     : Tkmrpc.Types.Byte_Sequence;
      Auth_Key    : Tkmrpc.Types.Byte_Sequence;
      Lifetime    : Tkmrpc.Types.Rel_Time_Type)
   is
      use Tkm.Utils;
   begin
      System (Command => "/bin/ip xfrm state add"
              & " src " & Source
              & " dst " & Destination
              & " proto esp spi" & SPI'Img
              & " replay-window 0"
              & " enc aes 0x" & To_Hex_String (Input => Enc_Key)
              & " auth hmac(sha512) 0x" & To_Hex_String (Input => Auth_Key)
              & " limit time-hard" & Lifetime'Img);
   end Add_State;

   -------------------------------------------------------------------------

   procedure Flush is
   begin
      System (Command => "/bin/ip xfrm policy flush");
      System (Command => "/bin/ip xfrm state flush");
   end Flush;

   -------------------------------------------------------------------------

   procedure System (Command : String)
   is
      Return_Code : Integer;
      Args        : GNAT.OS_Lib.Argument_List_Access;
   begin
      Args := GNAT.OS_Lib.Argument_String_To_List
        (Arg_String => Command);

      L.Log (Level   => L.Debug,
             Message => "Executing command '" & Command & "'");
      Return_Code := GNAT.OS_Lib.Spawn
        (Program_Name => Args (Args'First).all,
         Args         => Args (Args'First + 1 .. Args'Last));

      GNAT.OS_Lib.Free (Arg => Args);

      if Return_Code /= 0 then
         raise Xfrm_Error with "Error executing: '" & Command & "'";
      end if;
   end System;

end Tkm.Xfrm;
