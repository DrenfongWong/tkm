with Ada.Exceptions;
with Ada.Strings.Unbounded;
with Ada.Containers.Doubly_Linked_Lists;

with DOM.Core.Nodes;
with DOM.Core.Elements;
with DOM.Core.Documents;

with Input_Sources.File;

with Sax.Readers;

with Schema.Validators;
with Schema.Dom_Readers;
with Schema.Schema_Readers;

package body Tkm.Config.Xml
is

   package DR renames Schema.Dom_Readers;

   use type Ada.Containers.Count_Type;

   package Policies_Package is new Ada.Containers.Doubly_Linked_Lists
     (Element_Type => Security_Policy_Type);

   Policy_Tag    : constant String := "policy";
   Policy_Id_Tag : constant String := "id";
   Local_Tag     : constant String := "local";
   Remote_Tag    : constant String := "remote";
   Ip_Addr_Tag   : constant String := "ip";
   Lifetime_Tag  : constant String := "lifetime";
   Soft_Tag      : constant String := "soft";
   Hard_Tag      : constant String := "hard";
   Identity_Tag  : constant String := "identity";
   Cert_Tag      : constant String := "certificate";
   Net_Tag       : constant String := "net";

   function S
     (U : Ada.Strings.Unbounded.Unbounded_String)
      return String
      renames Ada.Strings.Unbounded.To_String;

   function U
     (S : String)
      return Ada.Strings.Unbounded.Unbounded_String
      renames Ada.Strings.Unbounded.To_Unbounded_String;

   function Get_Element_By_Tag_Name
     (Node     : DOM.Core.Element;
      Tag_Name : String)
      return DOM.Core.Node;
   --  Return child element of given E with specified tag name.

   function Get_Element_Value_By_Tag_Name
     (Node     : DOM.Core.Element;
      Tag_Name : String)
      return String;
   --  Return value of child element of given E with specified tag name. If the
   --  element does not exist an empty string is returned.

   function Get_Grammar (File : String) return Schema.Validators.XML_Grammar;
   --  Load grammar from given XML schema file.

   procedure Iterate
     (Data    : XML_Config;
      Process : not null access procedure
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String));
   --  Invokes given process procedure for each policy tag found in given xml
   --  config.

   function To_Array
     (List : Policies_Package.List)
      return Security_Policies_Type;
   --  Convert given policy list to security policy array type.

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type;
   --  Create identity type from given string.

   -------------------------------------------------------------------------

   function Get_Element_By_Tag_Name
     (Node     : DOM.Core.Element;
      Tag_Name : String)
      return DOM.Core.Node
   is
      List : DOM.Core.Node_List;
   begin
      List := DOM.Core.Elements.Get_Elements_By_Tag_Name
        (Elem => Node,
         Name => Tag_Name);

      if DOM.Core.Nodes.Length (List => List) = 0 then
         DOM.Core.Free (List => List);
         raise Config_Error with "Config element '" & Tag_Name & "' missing";
      end if;

      return Node : DOM.Core.Node do
         Node := DOM.Core.Nodes.Item (List  => List,
                                      Index => 0);
         DOM.Core.Free (List => List);
      end return;
   end Get_Element_By_Tag_Name;

   -------------------------------------------------------------------------

   function Get_Element_Value_By_Tag_Name
     (Node     : DOM.Core.Element;
      Tag_Name : String)
      return String
   is
      use type DOM.Core.Node;

      Val_Node : constant DOM.Core.Node
        := Get_Element_By_Tag_Name (Node     => Node,
                                    Tag_Name => Tag_Name);
   begin
      if Val_Node /= null
        and then DOM.Core.Nodes.Has_Child_Nodes (N => Val_Node)
      then
         return DOM.Core.Nodes.Node_Value
           (N => DOM.Core.Nodes.First_Child
              (N => Val_Node));
      else
         raise Config_Error with "Config element '" & Tag_Name
           & "' has no value";
      end if;
   end Get_Element_Value_By_Tag_Name;

   -------------------------------------------------------------------------

   function Get_Grammar (File : String) return Schema.Validators.XML_Grammar
   is
      Schema_Read : Schema.Schema_Readers.Schema_Reader;
      File_Input  : Input_Sources.File.File_Input;
   begin
      Input_Sources.File.Open (Filename => File,
                               Input    => File_Input);
      Schema.Schema_Readers.Parse (Parser => Schema_Read,
                                   Input  => File_Input);
      Input_Sources.File.Close (Input => File_Input);

      return Schema_Read.Get_Grammar;

   exception
      when E : others =>
         raise Config_Error with "Error reading XML schema '" & File & "': "
           & Ada.Exceptions.Exception_Message (X => E);
   end Get_Grammar;

   -------------------------------------------------------------------------

   procedure Iterate
     (Data    : XML_Config;
      Process : not null access procedure
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String))
   is
      package DC renames DOM.Core;

      List : DC.Node_List;
   begin
      List := DC.Documents.Get_Elements_By_Tag_Name
        (Doc      => DC.Document (Data),
         Tag_Name => Policy_Tag);

      for Index in 1 .. DC.Nodes.Length (List => List) loop
         declare
            Policy_Node   : constant DC.Node := DC.Nodes.Item
              (List  => List,
               Index => Index - 1);
            Id            : constant String := DC.Nodes.Node_Value
              (N => DC.Nodes.Get_Named_Item
                 (Map  => DC.Nodes.Attributes (N => Policy_Node),
                  Name => Policy_Id_Tag));
            Local_Identity  : Ada.Strings.Unbounded.Unbounded_String;
            Local_Addr      : Ada.Strings.Unbounded.Unbounded_String;
            Local_Net       : Ada.Strings.Unbounded.Unbounded_String;
            Local_Cert      : Ada.Strings.Unbounded.Unbounded_String;
            Remote_Identity : Ada.Strings.Unbounded.Unbounded_String;
            Remote_Addr     : Ada.Strings.Unbounded.Unbounded_String;
            Remote_Net      : Ada.Strings.Unbounded.Unbounded_String;
            Lifetime_Soft   : Ada.Strings.Unbounded.Unbounded_String;
            Lifetime_Hard   : Ada.Strings.Unbounded.Unbounded_String;

            Node : DC.Node;
         begin
            Node := Get_Element_By_Tag_Name (Node     => Policy_Node,
                                             Tag_Name => Local_Tag);
            Local_Identity := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Identity_Tag));
            Local_Addr := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Ip_Addr_Tag));
            Local_Net := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Net_Tag));
            Local_Cert := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Cert_Tag));

            Node  := Get_Element_By_Tag_Name (Node     => Policy_Node,
                                              Tag_Name => Remote_Tag);
            Remote_Identity := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Identity_Tag));
            Remote_Addr := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Ip_Addr_Tag));
            Remote_Net := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Net_Tag));

            Node  := Get_Element_By_Tag_Name (Node     => Policy_Node,
                                              Tag_Name => Lifetime_Tag);
            Lifetime_Soft := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Soft_Tag));
            Lifetime_Hard := U (Get_Element_Value_By_Tag_Name
              (Node     => Node,
               Tag_Name => Hard_Tag));

            Process (Id              => Id,
                     Local_Identity  => S (Local_Identity),
                     Local_Addr      => S (Local_Addr),
                     Local_Net       => S (Local_Net),
                     Local_Cert      => S (Local_Cert),
                     Remote_Identity => S (Remote_Identity),
                     Remote_Addr     => S (Remote_Addr),
                     Remote_Net      => S (Remote_Net),
                     Lifetime_Soft   => S (Lifetime_Soft),
                     Lifetime_Hard   => S (Lifetime_Hard));
         end;
      end loop;
      DOM.Core.Free (List => List);
   end Iterate;

   -------------------------------------------------------------------------

   procedure Parse
     (Data   : in out XML_Config;
      File   :        String;
      Schema :        String)
   is
      Reader     : DR.Tree_Reader;
      File_Input : Input_Sources.File.File_Input;
   begin
      Reader.Set_Grammar (Grammar => Get_Grammar (File => Schema));
      Reader.Set_Feature (Name  => Sax.Readers.Schema_Validation_Feature,
                          Value => True);

      begin
         Input_Sources.File.Open (Filename => File,
                                  Input    => File_Input);
         Reader.Parse (Input => File_Input);
         Input_Sources.File.Close (Input => File_Input);
         Data := XML_Config (Reader.Get_Tree);

      exception
         when E : others =>
            raise Config_Error with "Error parsing XML config '" & File & "': "
              & Ada.Exceptions.Exception_Message (X => E);
      end;
   end Parse;

   -------------------------------------------------------------------------

   function To_Array
     (List : Policies_Package.List)
      return Security_Policies_Type
   is
      use type Policies_Package.Cursor;

      subtype Index_Range is Natural range 0 .. Natural (List.Length);
      subtype Policies_Range is Index_Range range 1 .. Index_Range'Last;

      Policies : Security_Policies_Type (Policies_Range);
      Pos      : Policies_Package.Cursor := List.First;
      Idx      : Index_Range             := Index_Range'First;
   begin
      while Pos /= Policies_Package.No_Element loop
         Idx := Idx + 1;
         Policies (Idx) := Policies_Package.Element (Position => Pos);
         Policies_Package.Next (Position => Pos);
      end loop;
      return Policies;
   end To_Array;

   -------------------------------------------------------------------------

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type
   is

      --  Initialize with IKE identity header.

      Identity : Tkmrpc.Types.Identity_Type
        := (Size => Str'Length + 4,
            Data => (1      => 03,
                     others => 0));
   begin
      for I in Str'Range loop
         Identity.Data (I + 4) := Character'Pos (Str (I));
      end loop;

      return Identity;
   end To_Identity;

   -------------------------------------------------------------------------

   function To_Ike_Config (Data : XML_Config) return String
   is
      Script : Ada.Strings.Unbounded.Unbounded_String;

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String);
      --  Add new connection entry for given policy to script.

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String)
      is
         pragma Unreferenced (Lifetime_Soft, Lifetime_Hard);
      begin
         Ada.Strings.Unbounded.Append
           (Source   => Script,
            New_Item => "stroke add " & Id & " " & Local_Identity & " "
           & Remote_Identity & " " & Local_Addr & " " & Remote_Addr & " "
           & Local_Net & " " & Remote_Net & " "
           & Id & " "
            & "aes256-sha512-modp4096! "
            & Local_Cert & ASCII.LF);
         Ada.Strings.Unbounded.Append
           (Source   => Script,
            New_Item => "stroke route " & Id & ASCII.LF);
      end Process_Policy;
   begin
      Iterate (Data    => Data,
               Process => Process_Policy'Access);

      return S (Script);
   end To_Ike_Config;

   -------------------------------------------------------------------------

   function To_Tkm_Config (Data : XML_Config) return Config_Type
   is
      Policies : Policies_Package.List;

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String);
      --  Add new policy with given values to policy list.

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Local_Cert      : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String)
      is
         pragma Unreferenced (Local_Cert);

         Policy : Security_Policy_Type;
      begin
         Policy.Id              := Tkmrpc.Types.Sp_Id_Type'Value (Id);
         Policy.Local_Identity  := To_Identity (Str => Local_Identity);
         Policy.Local_Addr      := Anet.To_IPv4_Addr (Str => Local_Addr);
         Policy.Local_Net       := Anet.To_IPv4_Addr (Str => Local_Net);
         Policy.Remote_Identity := To_Identity (Str => Remote_Identity);
         Policy.Remote_Addr     := Anet.To_IPv4_Addr (Str => Remote_Addr);
         Policy.Remote_Net      := Anet.To_IPv4_Addr (Str => Remote_Net);
         Policy.Lifetime_Soft   := Tkmrpc.Types.Abs_Time_Type'Value
           (Lifetime_Soft);
         Policy.Lifetime_Hard   := Tkmrpc.Types.Abs_Time_Type'Value
           (Lifetime_Hard);

         Policies.Append (New_Item => Policy);
      end Process_Policy;
   begin
      Iterate (Data    => Data,
               Process => Process_Policy'Access);

      if Policies.Length = 0 then
         raise Config_Error with "No policies in XML config present";
      end if;

      return Cfg : Config_Type
        (Policy_Count => Positive (Policies.Length))
      do
         Cfg.Policies := To_Array (List => Policies);
      end return;
   end To_Tkm_Config;

end Tkm.Config.Xml;
