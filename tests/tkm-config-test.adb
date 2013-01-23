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

with Tkm.Config.Xml.Grammar;

with Schema.Validators;

package body Tkm.Config.Test
is

   -------------------------------------------------------------------------

   procedure Init_Grammar (File : String)
   is
      G : constant Schema.Validators.XML_Grammar
        := Xml.Grammar.Get_Grammar (File => File);
      pragma Unreferenced (G);
   begin
      null;
   end Init_Grammar;

   -------------------------------------------------------------------------

   procedure Load (Cfg : Config_Type)
   is
   begin
      Policy_Count := Cfg.Policy_Count;
      Current_Config.Policies (1 .. Policy_Count) := Cfg.Policies;
      L_Ident_Count := Cfg.Local_Ids_Count;
      Current_Config.L_Identities (1 .. L_Ident_Count) := Cfg.L_Identities;
   end Load;

end Tkm.Config.Test;
