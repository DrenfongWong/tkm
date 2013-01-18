package body Tkm.Config.Test
is

   -------------------------------------------------------------------------

   procedure Load (Cfg : Config_Type)
   is
   begin
      Policy_Count := Cfg.Policy_Count;
      Current_Config.Policies (1 .. Policy_Count) := Cfg.Policies;
   end Load;

end Tkm.Config.Test;
