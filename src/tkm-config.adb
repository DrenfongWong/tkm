with Ada.Exceptions;
with Ada.Text_IO.Text_Streams;

package body Tkm.Config
is

   -------------------------------------------------------------------------

   function Read (Filename : String) return Config_Type
   is
      File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open (File => File,
                        Mode => Ada.Text_IO.In_File,
                        Name => Filename);
      begin
         declare
            Config : constant Config_Type := Config_Type'Input
              (Ada.Text_IO.Text_Streams.Stream (File => File));
         begin
            Ada.Text_IO.Close (File => File);
            return Config;
         end;

      exception
         when others =>
            Ada.Text_IO.Close (File => File);
            raise;
      end;

   exception
      when E : others =>
         raise Config_Error with "Unable to read config from file '"
           & Filename & "': " & Ada.Exceptions.Exception_Name (E);
   end Read;

   -------------------------------------------------------------------------

   procedure Write
     (Config   : Config_Type;
      Filename : String)
   is
      File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create
        (File => File,
         Mode => Ada.Text_IO.Out_File,
         Name => Filename);
      Config_Type'Output
        (Ada.Text_IO.Text_Streams.Stream
           (File => File), Config);
      Ada.Text_IO.Close (File => File);

   exception
      when E : others =>
         raise Config_Error with "Unable to write config to file '"
           & Filename & "': " & Ada.Exceptions.Exception_Name (E);
   end Write;

end Tkm.Config;
