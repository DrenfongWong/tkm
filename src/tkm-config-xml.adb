with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Containers.Doubly_Linked_Lists;
with Ada.Containers.Ordered_Maps;

with DOM.Core.Nodes;
with DOM.Core.Elements;
with DOM.Core.Documents;

with Input_Sources.File;

with Sax.Readers;

with Schema.Dom_Readers;

with Tkm.Config.Xml.Tags;
with Tkm.Config.Xml.Grammar;

package body Tkm.Config.Xml
is

   package DR renames Schema.Dom_Readers;

   use Tkm.Config.Xml.Tags;

   use type Ada.Containers.Count_Type;
   use type Tkmrpc.Types.Li_Id_Type;

   package Policies_Package is new Ada.Containers.Doubly_Linked_Lists
     (Element_Type => Security_Policy_Type);

   type Local_Id_Type is record
      Id   : Tkmrpc.Types.Li_Id_Type;
      Name : Ada.Strings.Unbounded.Unbounded_String;
      Cert : Ada.Strings.Unbounded.Unbounded_String;
   end record;
   --  Local identity type as stored in the XML config.

   package Local_Ids_Pkg is new Ada.Containers.Ordered_Maps
     (Key_Type     => Tkmrpc.Types.Li_Id_Type,
      Element_Type => Local_Id_Type);

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

   function Get_Local_Identities (Data : XML_Config) return Local_Ids_Pkg.Map;
   --  Returns a map of all local identities in the given XML config.

   procedure For_Each_Node
     (Data     : XML_Config;
      Tag_Name : String;
      Process : not null access procedure (Node : DOM.Core.Node));
   --  Invoke the given process procedure for each tag with specified name in
   --  the given XML config.

   procedure Iterate
     (Data    : XML_Config;
      Process : not null access procedure
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String));
   --  Invokes given process procedure for each policy tag found in given xml
   --  config.

   procedure For_Each_L_Identity
     (Data    : XML_Config;
      Process : not null access procedure
        (Id          : String;
         Name        : String;
         Certificate : String));
   --  Invokes given process procedure for each local identity tag found in
   --  given xml config.

   function To_Array
     (List : Policies_Package.List)
      return Security_Policies_Type;
   --  Convert given policy list to security policy array type.

   function To_Array
     (Data : Local_Ids_Pkg.Map)
      return Identities.Local_Identities_Type;
   --  Convert given policy list to security policy array type.

   -------------------------------------------------------------------------

   procedure For_Each_L_Identity
     (Data    : XML_Config;
      Process : not null access procedure
        (Id          : String;
         Name        : String;
         Certificate : String))
   is
      package DC renames DOM.Core;

      procedure Process_L_Identity_Node (L_Id_Node : DOM.Core.Node);
      --  Process given local identitynode.

      procedure Process_L_Identity_Node (L_Id_Node : DOM.Core.Node)
      is
         Id            : constant String := DC.Nodes.Node_Value
           (N => DC.Nodes.Get_Named_Item
              (Map  => DC.Nodes.Attributes (N => L_Id_Node),
               Name => Id_Tag));
         Name : Ada.Strings.Unbounded.Unbounded_String;
         Cert : Ada.Strings.Unbounded.Unbounded_String;
      begin
         Name := U (Get_Element_Value_By_Tag_Name
           (Node     => L_Id_Node,
            Tag_Name => Identity_Tag));
         Cert := U (Get_Element_Value_By_Tag_Name
           (Node     => L_Id_Node,
            Tag_Name => Cert_Tag));

         Process (Id          => Id,
                  Name        => S (Name),
                  Certificate => S (Cert));
      end Process_L_Identity_Node;
   begin
      For_Each_Node (Data     => Data,
                     Tag_Name => L_Identity_Tag,
                     Process  => Process_L_Identity_Node'Access);
   end For_Each_L_Identity;

   -------------------------------------------------------------------------

   procedure For_Each_Node
     (Data     : XML_Config;
      Tag_Name : String;
      Process : not null access procedure (Node : DOM.Core.Node))
   is
      package DC renames DOM.Core;

      List : DC.Node_List;
   begin
      List := DC.Documents.Get_Elements_By_Tag_Name
        (Doc      => DC.Document (Data),
         Tag_Name => Tag_Name);

      for Index in 1 .. DC.Nodes.Length (List => List) loop
         Process (Node => DC.Nodes.Item
                  (List  => List,
                   Index => Index - 1));
      end loop;
      DOM.Core.Free (List => List);
   end For_Each_Node;

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

   function Get_Local_Identities (Data : XML_Config) return Local_Ids_Pkg.Map
   is
      L_Identities : Local_Ids_Pkg.Map;

      procedure Process_L_Identity
        (Id          : String;
         Name        : String;
         Certificate : String);
      --  Add new local identity with given values to local identities list.

      procedure Process_L_Identity
        (Id          : String;
         Name        : String;
         Certificate : String)
      is
         Identity : Local_Id_Type;
      begin
         Identity.Id   := Tkmrpc.Types.Li_Id_Type'Value (Id);
         Identity.Name := U (Name);
         Identity.Cert := U (Certificate);

         L_Identities.Insert (Key      => Identity.Id,
                              New_Item => Identity);
      end Process_L_Identity;
   begin
      For_Each_L_Identity (Data    => Data,
                           Process => Process_L_Identity'Access);

      return L_Identities;
   end Get_Local_Identities;

   -------------------------------------------------------------------------

   procedure Iterate
     (Data    : XML_Config;
      Process : not null access procedure
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String))
   is
      package DC renames DOM.Core;

      procedure Process_Policy_Node (Policy_Node : DOM.Core.Node);
      --  Process given policy node.

      procedure Process_Policy_Node (Policy_Node : DOM.Core.Node)
      is
         Id            : constant String := DC.Nodes.Node_Value
           (N => DC.Nodes.Get_Named_Item
              (Map  => DC.Nodes.Attributes (N => Policy_Node),
               Name => Id_Tag));
         Local_Identity  : Ada.Strings.Unbounded.Unbounded_String;
         Local_Addr      : Ada.Strings.Unbounded.Unbounded_String;
         Local_Net       : Ada.Strings.Unbounded.Unbounded_String;
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
            Tag_Name => Identity_Id_Tag));
         Local_Addr := U (Get_Element_Value_By_Tag_Name
           (Node     => Node,
            Tag_Name => Ip_Addr_Tag));
         Local_Net := U (Get_Element_Value_By_Tag_Name
           (Node     => Node,
            Tag_Name => Net_Tag));

         Node := Get_Element_By_Tag_Name (Node     => Policy_Node,
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

         Node := Get_Element_By_Tag_Name (Node     => Policy_Node,
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
                  Remote_Identity => S (Remote_Identity),
                  Remote_Addr     => S (Remote_Addr),
                  Remote_Net      => S (Remote_Net),
                  Lifetime_Soft   => S (Lifetime_Soft),
                  Lifetime_Hard   => S (Lifetime_Hard));
      end Process_Policy_Node;
   begin
      For_Each_Node (Data     => Data,
                     Tag_Name => Policy_Tag,
                     Process  => Process_Policy_Node'Access);
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
      Reader.Set_Grammar (Grammar => Grammar.Get_Grammar (File => Schema));
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

   function To_Array
     (Data : Local_Ids_Pkg.Map)
      return Identities.Local_Identities_Type
   is
      use type Local_Ids_Pkg.Cursor;

      subtype Index_Range is Natural range 0 .. Natural (Data.Length);
      subtype Idents_Range is Index_Range range 1 .. Index_Range'Last;

      Idents : Identities.Local_Identities_Type (Idents_Range);
      Pos    : Local_Ids_Pkg.Cursor := Data.First;
      Idx    : Index_Range          := Index_Range'First;
   begin
      while Pos /= Local_Ids_Pkg.No_Element loop
         Idx := Idx + 1;
         declare
            Elem : constant Local_Id_Type := Local_Ids_Pkg.Element
              (Position => Pos);
         begin
            Idents (Idx) := (Id => Elem.Id,
                             Name => Identities.To_Identity
                               (Str => S (Elem.Name)));
         end;
         Local_Ids_Pkg.Next (Position => Pos);
      end loop;
      return Idents;
   end To_Array;

   -------------------------------------------------------------------------

   function To_Ike_Config (Data : XML_Config) return String
   is
      L_Identities : constant Local_Ids_Pkg.Map
        := Get_Local_Identities (Data => Data);

      Conf_File : Ada.Strings.Unbounded.Unbounded_String;

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String);
      --  Add new connection entry for given policy to script.

      ----------------------------------------------------------------------

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String)
      is
         pragma Unreferenced (Local_Net, Remote_Net);

         L_Id    : constant Tkmrpc.Types.Li_Id_Type
           := Tkmrpc.Types.Li_Id_Type'Value (Local_Identity);
         L_Ident : constant Local_Id_Type
           := L_Identities.Element (Key => L_Id);

         procedure Add_Entry
           (Source : in out Ada.Strings.Unbounded.Unbounded_String;
            Key    :        String;
            Value  :        String);
         --  Add specified key/value entry to source string. If value is empty
         --  nothing is added.

         procedure Add_Entry
           (Source : in out Ada.Strings.Unbounded.Unbounded_String;
            Key    :        String;
            Value  :        String)
         is
            Space : constant String := "    ";
         begin
            if Value'Length > 0 then
               Ada.Strings.Unbounded.Append
                 (Source   => Conf_File,
                  New_Item => Space & Key & "=" & Value & ASCII.LF);
            end if;
         end Add_Entry;
      begin
         Ada.Strings.Unbounded.Append
           (Source   => Conf_File,
            New_Item => ASCII.LF & "conn conn" & Id & ASCII.LF);
         Add_Entry (Source => Conf_File,
                    Key    => "reqid",
                    Value  => Id);
         Add_Entry (Source => Conf_File,
                    Key    => "left",
                    Value  => Local_Addr);
         Add_Entry (Source => Conf_File,
                    Key    => "leftid",
                    Value  => S (L_Ident.Name));
         Add_Entry (Source => Conf_File,
                    Key    => "leftcert",
                    Value  => S (L_Ident.Cert));
         Add_Entry (Source => Conf_File,
                    Key    => "right",
                    Value  => Remote_Addr);
         Add_Entry (Source => Conf_File,
                    Key    => "rightid",
                    Value  => Remote_Identity);
         Add_Entry (Source => Conf_File,
                    Key    => "lifetime",
                    Value  => Lifetime_Hard);

         declare
            use Tkmrpc.Types;

            Margin : constant Rel_Time_Type
              := Rel_Time_Type'Value
                (Lifetime_Hard) - Rel_Time_Type'Value (Lifetime_Soft);
         begin
            Add_Entry (Source => Conf_File,
                       Key    => "margintime",
                       Value  => Ada.Strings.Fixed.Trim
                         (Source => Margin'Img,
                          Side   => Ada.Strings.Left));
         end;

         --  Add fixed entries

         Add_Entry (Source => Conf_File,
                    Key    => "ike",
                    Value  => "aes256-sha512-modp4096!");
         Add_Entry (Source => Conf_File,
                    Key    => "esp",
                    Value  => "aes256-sha512-modp4096!");
         Add_Entry (Source => Conf_File,
                    Key    => "type",
                    Value  => "transport");
         Add_Entry (Source => Conf_File,
                    Key    => "auto",
                    Value  => "route");
      end Process_Policy;
   begin
      Iterate (Data    => Data,
               Process => Process_Policy'Access);

      return S (Conf_File);
   end To_Ike_Config;

   -------------------------------------------------------------------------

   function To_Tkm_Config (Data : XML_Config) return Config_Type
   is
      L_Identities : constant Local_Ids_Pkg.Map
        := Get_Local_Identities (Data => Data);

      Policies : Policies_Package.List;

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String);
      --  Add new policy with given values to policy list.

      ----------------------------------------------------------------------

      procedure Process_Policy
        (Id              : String;
         Local_Identity  : String;
         Local_Addr      : String;
         Local_Net       : String;
         Remote_Identity : String;
         Remote_Addr     : String;
         Remote_Net      : String;
         Lifetime_Soft   : String;
         Lifetime_Hard   : String)
      is
         Policy : Security_Policy_Type;
      begin
         Policy.Id              := Tkmrpc.Types.Sp_Id_Type'Value (Id);
         Policy.Local_Identity  := Tkmrpc.Types.Li_Id_Type'Value
           (Local_Identity);
         Policy.Local_Addr      := Anet.To_IPv4_Addr (Str => Local_Addr);
         Policy.Local_Net       := Anet.To_IPv4_Addr (Str => Local_Net);
         Policy.Remote_Identity := Identities.To_Identity
           (Str => Remote_Identity);
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

      return Cfg : Config_Type
        (Version         => Version,
         Policy_Count    => Positive (Policies.Length),
         Local_Ids_Count => Positive (L_Identities.Length))
      do
         Cfg.Policies     := To_Array (List => Policies);
         Cfg.L_Identities := To_Array (Data => L_Identities);
      end return;
   end To_Tkm_Config;

end Tkm.Config.Xml;
