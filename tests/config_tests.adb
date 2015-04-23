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

with System.Assertions;

with Anet.Util;
with Anet.OS;

with Tkm.Config.Xml;
with Tkm.Config.Test;
with Tkm.Identities;

package body Config_Tests is

   use Ahven;
   use Tkm;
   use Tkm.Config.Test;

   -------------------------------------------------------------------------

   procedure Get_Local_Identity
   is
      use type Identities.Local_Identity_Type;
   begin
      Config.Clear;
      Config.Test.Load (Cfg => Ref_Config);

      Assert (Condition => Config.Get_Local_Identity
              (Id => Ref_Local_Ids (1).Id) = Ref_Local_Ids (1),
              Message   => "Local identity mismatch");

      begin
         declare
            Dummy : constant Identities.Local_Identity_Type
              := Config.Get_Local_Identity (Id => 42);
            pragma Unreferenced (Dummy);
         begin
            Fail (Message => "Expected config error");
         end;

      exception
         when Config.Config_Error => null;
      end;
   end Get_Local_Identity;

   -------------------------------------------------------------------------

   procedure Get_Policy
   is
      use type Config.Security_Policy_Type;
   begin
      Config.Clear;
      begin
         declare
            Dummy : Config.Security_Policy_Type := Config.Get_Policy (Id => 1);
            pragma Unreferenced (Dummy);
         begin
            Fail (Message => "Assertion error expected");
         end;

      exception
         when System.Assertions.Assert_Failure => null;
      end;

      Config.Test.Load (Cfg => Ref_Config);

      Assert (Condition => Config.Get_Policy
              (Id => Ref_Policies (1).Id) = Ref_Policies (1),
              Message   => "Policy mismatch");
   end Get_Policy;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Config tests");
      T.Add_Test_Routine
        (Routine => Write_And_Read_Config'Access,
         Name    => "Write and read config file");
      T.Add_Test_Routine
        (Routine => Load_Config'Access,
         Name    => "Load config from file");
      T.Add_Test_Routine
        (Routine => Xml_To_Tkm_Config'Access,
         Name    => "Convert Xml to Tkm config");
      T.Add_Test_Routine
        (Routine => Xml_To_Ike_Config'Access,
         Name    => "Convert Xml to Ike config");
      T.Add_Test_Routine
        (Routine => Get_Policy'Access,
         Name    => "Get policy from config");
      T.Add_Test_Routine
        (Routine => Iterate_Policies'Access,
         Name    => "Iterate over policies in config");
      T.Add_Test_Routine
        (Routine => Get_Local_Identity'Access,
         Name    => "Get local identity from config");
      T.Add_Test_Routine
        (Routine => Version_Check'Access,
         Name    => "Load config with different version");

      --  Make sure XML grammar is parsed.

      Config.Test.Init_Grammar (File => "schema/tkmconfig.xsd");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Iterate_Policies
   is
      Counter : Natural := 0;

      procedure Inc_Counter (Policy : Config.Security_Policy_Type);
      --  Increment counter for each policy.

      procedure Inc_Counter (Policy : Config.Security_Policy_Type)
      is
         pragma Unreferenced (Policy);
      begin
         Counter := Counter + 1;
      end Inc_Counter;
   begin
      Config.Test.Load (Cfg => Ref_Config);

      Config.Iterate (Process => Inc_Counter'Access);
      Assert (Condition => Counter = Ref_Config.Policy_Count,
              Message   => "Counter mismatch");
   end Iterate_Policies;

   -------------------------------------------------------------------------

   procedure Load_Config
   is
      use type Config.Security_Policy_Type;

      Tmp_Filename : constant String
        := "/tmp/tkm.test-config-" & Anet.Util.Random_String (Len => 8);
   begin
      Assert (Condition => Config.Is_Empty,
              Message   => "Config is not empty");

      Config.Write
        (Config   => Ref_Config,
         Filename => Tmp_Filename);

      Config.Load (Filename => Tmp_Filename);
      Assert (Condition => not Config.Is_Empty,
              Message   => "Config is empty");
      Assert (Condition => Config.Get_Policy_Count = Ref_Config.Policy_Count,
              Message   => "Policy count mismatch");

      Config.Clear;
      Assert (Condition => Config.Is_Empty,
              Message   => "Config is not empty");

      Anet.OS.Delete_File
        (Filename       => Tmp_Filename,
         Ignore_Missing => False);

   exception
      when others =>
         Anet.OS.Delete_File
           (Filename       => Tmp_Filename,
            Ignore_Missing => False);
         raise;
   end Load_Config;

   -------------------------------------------------------------------------

   procedure Version_Check
   is
   begin
      Config.Load (Filename => "data/version0.cfg");
      Fail (Message => "Exception expected");

   exception
      when Config.Config_Error => null;
   end Version_Check;

   -------------------------------------------------------------------------

   procedure Write_And_Read_Config
   is
      use type Config.Config_Type;

      Tmp_Filename : constant String
        := "/tmp/tkm.test-config-" & Anet.Util.Random_String (Len => 8);
   begin
      Config.Write
        (Config   => Ref_Config,
         Filename => Tmp_Filename);

      declare
         R_Cfg : constant Config.Config_Type := Config.Read
           (Filename => Tmp_Filename);
      begin
         Assert (Condition => R_Cfg = Ref_Config,
                 Message   => "Configs mismatch");
      end;

      Anet.OS.Delete_File
        (Filename       => Tmp_Filename,
         Ignore_Missing => False);

   exception
      when others =>
         Anet.OS.Delete_File
           (Filename       => Tmp_Filename,
            Ignore_Missing => False);
         raise;
   end Write_And_Read_Config;

   -------------------------------------------------------------------------

   procedure Xml_To_Ike_Config
   is
      Cfg : Config.Xml.XML_Config;
   begin
      Config.Xml.Parse (Data   => Cfg,
                        File   => "data/refconfig.xml",
                        Schema => "schema/tkmconfig.xsd");
      Assert
        (Condition => Config.Xml.To_Ike_Config (Data => Cfg) = Ref_Ike_Cfg,
         Message   => "Converted Ike config mismatch");
   end Xml_To_Ike_Config;

   -------------------------------------------------------------------------

   procedure Xml_To_Tkm_Config
   is
      use type Config.Config_Type;

      Cfg : Config.Xml.XML_Config;
   begin
      Config.Xml.Parse (Data   => Cfg,
                        File   => "data/refconfig.xml",
                        Schema => "schema/tkmconfig.xsd");

      declare
         Tkm_Cfg : constant Config.Config_Type
           := Config.Xml.To_Tkm_Config (Data => Cfg);
      begin
         Assert (Condition => Tkm_Cfg = Ref_Config,
                 Message   => "Converted config mismatch");
      end;
   end Xml_To_Tkm_Config;

end Config_Tests;
