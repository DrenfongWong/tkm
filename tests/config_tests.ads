with Ahven.Framework;

package Config_Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Write_And_Read_Config;
   --  Write and read configuration file.

   procedure Xml_To_Tkm_Config;
   --  Read XML configuration file and convert to TKM config.

end Config_Tests;
