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
