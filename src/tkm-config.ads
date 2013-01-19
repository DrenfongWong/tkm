with Anet;

package Tkm.Config
is

   Max_Policy_Count : constant := 32;
   --  Maximum number of policies.

   Max_Local_Identities_Count : constant := 32;
   --  Maximum number of local identities.

   type Security_Policy_Type is record
      Id              : Tkmrpc.Types.Sp_Id_Type;
      Local_Identity  : Tkmrpc.Types.Li_Id_Type;
      Local_Addr      : Anet.IPv4_Addr_Type;
      Local_Net       : Anet.IPv4_Addr_Type;
      Remote_Identity : Tkmrpc.Types.Identity_Type;
      Remote_Addr     : Anet.IPv4_Addr_Type;
      Remote_Net      : Anet.IPv4_Addr_Type;
      Lifetime_Soft   : Tkmrpc.Types.Abs_Time_Type;
      Lifetime_Hard   : Tkmrpc.Types.Abs_Time_Type;
   end record;
   --  Security policy describing a connection.

   Null_Security_Policy : constant Security_Policy_Type;

   type Security_Policies_Type is array (Positive range <>)
     of Security_Policy_Type;

   type Local_Identity_Type is record
      Id   : Tkmrpc.Types.Li_Id_Type;
      Name : Tkmrpc.Types.Identity_Type;
   end record;
   --  Identity type connects identity id with a name.

   Null_Local_Identity : constant Local_Identity_Type;

   type Local_Identities_Type is array (Positive range <>)
     of Local_Identity_Type;

   type Config_Type
     (Policy_Count    : Positive;
      Local_Ids_Count : Positive)
   is record
      Policies     : Security_Policies_Type (1 .. Policy_Count);
      L_Identities : Local_Identities_Type (1 .. Local_Ids_Count);
   end record;
   --  TKM Configuration.

   function Read (Filename : String) return Config_Type;
   --  Load config from file specified by filename.

   procedure Write
     (Config   : Config_Type;
      Filename : String);
   --  Write configuration to file specified by filename.

   procedure Load (Filename : String);
   --  Load config from given file.

   procedure Clear;
   --  Clear configuration.

   function Is_Empty return Boolean;
   --  Returns True if no configuration is present.

   function Get_Policy_Count return Natural;
   --  Returns number of policies present in current config.

   function Get_Policy
     (Id : Tkmrpc.Types.Sp_Id_Type)
      return Security_Policy_Type
   with
     Pre => not Is_Empty;
   --  Returns policy with given id from the config. A config error is raised
   --  if no policy with given id exists.

   function Get_Local_Identity
     (Id : Tkmrpc.Types.Li_Id_Type)
      return Local_Identity_Type
   with
     Pre => not Is_Empty;
   --  Returns local identity with given id from the config. A config error is
   --  raised if no local identity with given id exists.

   procedure Iterate
     (Process : not null access procedure (Policy : Security_Policy_Type))
   with
     Pre => not Is_Empty;
   --  Calls the given process procedure for each policy in the config.

   Config_Error : exception;

private

   Null_Security_Policy : constant Security_Policy_Type
     := (Id              => Tkmrpc.Types.Sp_Id_Type'First,
         Local_Identity  => Tkmrpc.Types.Li_Id_Type'First,
         Local_Addr      => Anet.Any_Addr,
         Local_Net       => Anet.Any_Addr,
         Remote_Identity => Tkmrpc.Types.Null_Identity_Type,
         Remote_Addr     => Anet.Any_Addr,
         Remote_Net      => Anet.Any_Addr,
         Lifetime_Soft   => Tkmrpc.Types.Abs_Time_Type'First,
         Lifetime_Hard   => Tkmrpc.Types.Abs_Time_Type'First);

   Null_Local_Identity : constant Local_Identity_Type
     := (Id => Tkmrpc.Types.Li_Id_Type'First,
         Name => Tkmrpc.Types.Null_Identity_Type);

   Policy_Count   : Natural := 0;
   L_Ident_Count  : Natural := 0;
   Current_Config : Config_Type
     (Policy_Count    => Max_Policy_Count,
      Local_Ids_Count => Max_Local_Identities_Count);

end Tkm.Config;
