with System.Assertions;

with Anet.Util;
with Anet.OS;

with Tkm.Config.Xml;
with Tkm.Config.Test;

package body Config_Tests is

   use Ahven;
   use Tkm;

   Ref_Local_Ids : constant Config.Local_Identities_Type (1 .. 1)
     := (1 =>
           (Id   => 1,
            Name =>
              (Size => 24,
               Data => (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#,
                        16#63#, 16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#,
                        16#6E#, 16#67#, 16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#,
                        16#6F#, 16#72#, 16#67#, others => 0))));
   --  Reference local identities.

   Ref_Policies : constant Config.Security_Policies_Type (1 .. 2)
     := (1 => (Id              => 1,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 0, 2),
               Remote_Identity => Config.Remote_Id,
               Remote_Addr     => (192, 168, 0, 3),
               Remote_Net      => (192, 168, 0, 3),
               Lifetime_Soft   => Config.Lifetime_Soft,
               Lifetime_Hard   => Config.Lifetime_Hard),
         2 => (Id            => 2,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 100, 0),
               Remote_Identity => Config.Remote_Id,
               Remote_Addr     => (192, 168, 0, 4),
               Remote_Net      => (192, 168, 200, 0),
               Lifetime_Soft => Config.Lifetime_Soft,
               Lifetime_Hard => Config.Lifetime_Hard));
   --  Reference policies.

   Ref_Config   : constant Config.Config_Type
     := (Policy_Count    => Ref_Policies'Length,
         Policies        => Ref_Policies,
         Local_Ids_Count => Ref_Local_Ids'Length,
         L_Identities    => Ref_Local_Ids);
   --  Reference config.

   Ref_Ike_Cfg  : constant String
     := "stroke add 1 alice@strongswan.org bob@strongswan.org 192.168.0.2 " &
   "192.168.0.3 192.168.0.2 192.168.0.3 1 aes256-sha512-modp4096! " &
   "aliceCert.pem" & ASCII.LF &
   "stroke route 1" & ASCII.LF &
   "stroke add 2 alice@strongswan.org bob@strongswan.org 192.168.0.2 " &
   "192.168.0.4 192.168.100.0 192.168.200.0 2 aes256-sha512-modp4096! " &
   "aliceCert.pem" & ASCII.LF &
   "stroke route 2" & ASCII.LF;

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
