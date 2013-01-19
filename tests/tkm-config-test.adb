package body Tkm.Config.Test
is

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
