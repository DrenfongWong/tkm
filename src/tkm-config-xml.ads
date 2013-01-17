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

   function Convert (Data : XML_Config) return Config_Type;
   --  Convert given XML document to TKM config type.

private

   type XML_Config is new DOM.Core.Document;

end Tkm.Config.Xml;
