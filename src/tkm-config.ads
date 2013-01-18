with Anet;

package Tkm.Config
is

   Local_Addr : constant String := "152.96.15.32";
   --  ESP source address.

   Peer_Addr : constant String := "152.96.15.60";
   --  ESP destination address.

   Local_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 24,
         Data =>
           (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#, 16#63#,
            16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#, 16#6E#, 16#67#,
            16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#, 16#6F#, 16#72#, 16#67#,
            others => 0));
   --  Local ID: alice@strongswan.org.

   Remote_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 22,
         Data =>
           (16#03#, 16#00#, 16#00#, 16#00#, 16#62#, 16#6f#, 16#62#, 16#40#,
            16#73#, 16#74#, 16#72#, 16#6f#, 16#6e#, 16#67#, 16#73#, 16#77#,
            16#61#, 16#6e#, 16#2e#, 16#6f#, 16#72#, 16#67#, others => 0));
   --  Remote ID: bob@strongswan.org.

   Lifetime_Hard : constant := 60;
   --  ESP SA lifetime in seconds (hard).

   Lifetime_Soft : constant := 30;
   --  ESP SA lifetime in seconds (soft).

   Max_Policy_Count : constant := 32;
   --  Maximum number of policies.

   type Security_Policy_Type is record
      Id              : Tkmrpc.Types.Sp_Id_Type;
      Local_Identity  : Tkmrpc.Types.Identity_Type;
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

   type Config_Type
     (Policy_Count : Positive)
   is record
      Policies : Security_Policies_Type (1 .. Policy_Count);
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

   Config_Error : exception;

private

   Null_Security_Policy : constant Security_Policy_Type
     := (Id              => Tkmrpc.Types.Sp_Id_Type'First,
         Local_Identity  => Tkmrpc.Types.Null_Identity_Type,
         Local_Addr      => Anet.Any_Addr,
         Local_Net       => Anet.Any_Addr,
         Remote_Identity => Tkmrpc.Types.Null_Identity_Type,
         Remote_Addr     => Anet.Any_Addr,
         Remote_Net      => Anet.Any_Addr,
         Lifetime_Soft   => Tkmrpc.Types.Abs_Time_Type'First,
         Lifetime_Hard   => Tkmrpc.Types.Abs_Time_Type'First);

   Policy_Count   : Natural := 0;
   Current_Config : Config_Type (Policy_Count => Max_Policy_Count);

end Tkm.Config;
