with Schema.Validators;

package Tkm.Config.Xml.Grammar
is

   function Get_Grammar (File : String) return Schema.Validators.XML_Grammar;
   --  Load grammar from given XML schema file.

end Tkm.Config.Xml.Grammar;
