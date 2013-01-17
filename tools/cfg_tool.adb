with Ada.Text_IO;
with Ada.Exceptions;
with Ada.Command_Line;
with Ada.Strings.Unbounded;

with GNAT.Command_Line;

with Tkm.Version;
with Tkm.Config.Xml;

procedure Cfg_Tool
is

   use Ada.Strings.Unbounded;

   procedure Print_Usage (Msg : String);
   --  Print usage information and set exit status to failure.

   procedure Print_Usage (Msg : String)
   is
      use Ada.Command_Line;
   begin
      Ada.Text_IO.Put_Line (Item => Msg);
      Ada.Text_IO.Put_Line
        (Item => "Usage: " & Command_Name & " -c <config> -i <ikefile> "
         & "-t <tkmfile> -s <schema>");
      Ada.Text_IO.Put_Line ("  -c config file");
      Ada.Text_IO.Put_Line ("  -i filename of IKE script to be written");
      Ada.Text_IO.Put_Line ("  -t filename of TKM config to be written");
      Ada.Text_IO.Put_Line
        ("  -s XML schema file (optional, default: schema/tkmconfig.xsd)");
      Ada.Text_IO.Put_Line ("  -v version information");
      Ada.Command_Line.Set_Exit_Status (Code => Failure);
   end Print_Usage;

   Xsd_File : Unbounded_String := To_Unbounded_String ("schema/tkmconfig.xsd");
   Cfg_File : Unbounded_String;
   Ike_File : Unbounded_String;
   Tkm_File : Unbounded_String;
   Config   : Tkm.Config.Xml.XML_Config;
begin
   begin
      loop
         case GNAT.Command_Line.Getopt ("c: i: t: s: v") is
            when ASCII.NUL => exit;
            when 'c'       =>
               Cfg_File := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 'i'       =>
               Ike_File := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 's'       =>
               Xsd_File := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 't'       =>
               Tkm_File := To_Unbounded_String
                 (GNAT.Command_Line.Parameter);
            when 'v'       =>
               Ada.Text_IO.Put_Line
                 ("TKM config tool (" & Tkm.Version.Version_String & ")");
               Ada.Command_Line.Set_Exit_Status
                 (Code => Ada.Command_Line.Success);
               return;
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
      Print_Usage (Msg => "No config file specified");
      return;
   end if;

   if Ike_File = Null_Unbounded_String
     and then Tkm_File = Null_Unbounded_String
   then
      Print_Usage (Msg => "No IKE and no TKM file specified");
   end if;

   Tkm.Config.Xml.Parse (Data   => Config,
                         File   => To_String (Cfg_File),
                         Schema => To_String (Xsd_File));

   if Ike_File /= Null_Unbounded_String then
      declare
         File : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Create
           (File => File,
            Mode => Ada.Text_IO.Out_File,
            Name => To_String (Ike_File));
         Ada.Text_IO.Put
           (File => File,
            Item => Tkm.Config.Xml.To_Ike_Config (Data => Config));
         Ada.Text_IO.Close (File => File);
      end;
   end if;

   if Tkm_File /= Null_Unbounded_String then
      Tkm.Config.Write
        (Config   => Tkm.Config.Xml.To_Tkm_Config (Data => Config),
         Filename => To_String (Tkm_File));
   end if;

   Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Success);

exception
   when E : others =>
      Ada.Text_IO.Put_Line ("Terminating due to error");
      Ada.Text_IO.Put_Line (Ada.Exceptions.Exception_Information (X => E));
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
end Cfg_Tool;
