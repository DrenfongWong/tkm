with Ahven.Framework;

package Config_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Write_And_Read_Config;
   --  Write and read configuration file.

   procedure Load_Config;
   --  Load config from file.

   procedure Version_Check;
   --  Load config with different version.

   procedure Xml_To_Tkm_Config;
   --  Read XML configuration file and convert to TKM config.

   procedure Xml_To_Ike_Config;
   --  Read XML configuration file and convert to IKE config.

   procedure Get_Policy;
   --  Get policy from config.

   procedure Iterate_Policies;
   --  Iterate over all policies.

   procedure Get_Local_Identity;
   --  Get local identity from config.

end Config_Tests;
