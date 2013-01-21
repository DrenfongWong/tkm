package Tkm.Config.Test
is

   Alice_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 24,
         Data =>
           (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#, 16#63#,
            16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#, 16#6E#, 16#67#,
            16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#, 16#6F#, 16#72#, 16#67#,
            others => 0));
   --  alice@strongswan.org.

   Bod_Id : constant Tkmrpc.Types.Identity_Type
     := (Size => 22,
         Data =>
           (16#03#, 16#00#, 16#00#, 16#00#, 16#62#, 16#6f#, 16#62#, 16#40#,
            16#73#, 16#74#, 16#72#, 16#6f#, 16#6e#, 16#67#, 16#73#, 16#77#,
            16#61#, 16#6e#, 16#2e#, 16#6f#, 16#72#, 16#67#, others => 0));
   --  bob@strongswan.org.

   Lifetime_Hard : constant := 60;
   --  ESP SA lifetime in seconds (hard).

   Lifetime_Soft : constant := 30;
   --  ESP SA lifetime in seconds (soft).

   Ref_Local_Ids : constant Config.Local_Identities_Type (1 .. 1)
     := (1 => (Id   => 1,
               Name => Alice_Id));
   --  Reference local identities.

   Ref_Policies : constant Config.Security_Policies_Type (1 .. 2)
     := (1 => (Id              => 1,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 0, 2),
               Remote_Identity => Bod_Id,
               Remote_Addr     => (192, 168, 0, 3),
               Remote_Net      => (192, 168, 0, 3),
               Lifetime_Soft   => Lifetime_Soft,
               Lifetime_Hard   => Lifetime_Hard),
         2 => (Id            => 2,
               Local_Identity  => 1,
               Local_Addr      => (192, 168, 0, 2),
               Local_Net       => (192, 168, 100, 0),
               Remote_Identity => Bod_Id,
               Remote_Addr     => (192, 168, 0, 4),
               Remote_Net      => (192, 168, 200, 0),
               Lifetime_Soft => Lifetime_Soft,
               Lifetime_Hard => Lifetime_Hard));
   --  Reference policies.

   Ref_Config   : constant Config.Config_Type
     := (Policy_Count    => Ref_Policies'Length,
         Policies        => Ref_Policies,
         Local_Ids_Count => Ref_Local_Ids'Length,
         L_Identities    => Ref_Local_Ids);
   --  Reference config.

   Ref_Ike_Cfg  : constant String
     := "stroke add 1 alice@strongswan.org bob@strongswan.org 192.168.0.2 " &
   "192.168.0.3 192.168.0.2 192.168.0.3 1 aes256-sha512-modp4096! " &
   "aliceCert.pem" & ASCII.LF &
   "stroke route 1" & ASCII.LF &
   "stroke add 2 alice@strongswan.org bob@strongswan.org 192.168.0.2 " &
   "192.168.0.4 192.168.100.0 192.168.200.0 2 aes256-sha512-modp4096! " &
   "aliceCert.pem" & ASCII.LF &
   "stroke route 2" & ASCII.LF;

   procedure Load (Cfg : Config_Type);
   --  Load given config.

   procedure Init_Grammar (File : String);
   --  Initialize grammar.

end Tkm.Config.Test;
