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
