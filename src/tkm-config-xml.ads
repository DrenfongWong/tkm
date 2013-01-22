private with DOM.Core;

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

   type XML_Config is new DOM.Core.Document;

end Tkm.Config.Xml;
