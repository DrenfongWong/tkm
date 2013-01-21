with Ada.Exceptions;

with Input_Sources.File;

with Schema.Schema_Readers;

package body Tkm.Config.Xml.Grammar
is

   Current_Grammar : Schema.Validators.XML_Grammar
     := Schema.Validators.No_Grammar;

   -------------------------------------------------------------------------

   function Get_Grammar (File : String) return Schema.Validators.XML_Grammar
   is
      use type Schema.Validators.XML_Grammar;

      Schema_Read : Schema.Schema_Readers.Schema_Reader;
      File_Input  : Input_Sources.File.File_Input;
   begin
      if Current_Grammar = Schema.Validators.No_Grammar then
         Input_Sources.File.Open (Filename => File,
                                  Input    => File_Input);
         Schema.Schema_Readers.Parse (Parser => Schema_Read,
                                      Input  => File_Input);
         Input_Sources.File.Close (Input => File_Input);
         Current_Grammar := Schema_Read.Get_Grammar;
      end if;

      return Current_Grammar;

   exception
      when E : others =>
         raise Config_Error with "Error reading XML schema '" & File & "': "
           & Ada.Exceptions.Exception_Message (X => E);
   end Get_Grammar;

end Tkm.Config.Xml.Grammar;
