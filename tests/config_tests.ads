with Ahven.Framework;

package Config_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Write_And_Read_Config;
   --  Write and read configuration file.

   procedure Load_Config;
   --  Load config from file.

   procedure Xml_To_Tkm_Config;
   --  Read XML configuration file and convert to TKM config.

   procedure Xml_To_Ike_Config;
   --  Read XML configuration file and convert to IKE config.

   procedure Get_Policy;
   --  Get policy from config.

   procedure Iterate_Policies;
   --  Iterate over all policies.

end Config_Tests;
