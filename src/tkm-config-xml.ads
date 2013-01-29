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

private with DOM.Core;
private with Ada.Finalization;

package Tkm.Config.Xml
is

   type XML_Config is private;

   procedure Parse
     (Data   : in out XML_Config;
      File   :        String;
      Schema :        String);
   --  Parse the contents of given file into the DOM data structure. The XML
   --  data is validated against the given XML schema.

   function To_Tkm_Config (Data : XML_Config) return Config_Type;
   --  Create TKM config instance from given XML document.

   function To_Ike_Config (Data : XML_Config) return String;
   --  Create config file in strongSwan's ipsec.conf format from given XML
   --  document.

private

   type XML_Config is new Ada.Finalization.Controlled with record
      Doc : DOM.Core.Document;
   end record;

   overriding
   procedure Finalize (Object : in out XML_Config);
   --  Free XML document.

end Tkm.Config.Xml;
