package Tkm.Config
is

   Pre_Shared_Key : constant String := "foobar";
   --  Pre-shared key used for (PSK) authentification.

   Local_Addr : constant String := "152.96.15.32";
   --  ESP source address.

   Peer_Addr : constant String := "152.96.15.60";
   --  ESP destination address.

   Local_Id : constant Tkmrpc.Types.Idx_Type
     := (Size => 93,
         Data =>
           (16#09#, 16#00#, 16#00#, 16#00#, 16#30#, 16#57#, 16#31#, 16#0b#,
            16#30#, 16#09#, 16#06#, 16#03#, 16#55#, 16#04#, 16#06#, 16#13#,
            16#02#, 16#43#, 16#48#, 16#31#, 16#19#, 16#30#, 16#17#, 16#06#,
            16#03#, 16#55#, 16#04#, 16#0a#, 16#13#, 16#10#, 16#4c#, 16#69#,
            16#6e#, 16#75#, 16#78#, 16#20#, 16#73#, 16#74#, 16#72#, 16#6f#,
            16#6e#, 16#67#, 16#53#, 16#77#, 16#61#, 16#6e#, 16#31#, 16#0e#,
            16#30#, 16#0c#, 16#06#, 16#03#, 16#55#, 16#04#, 16#0b#, 16#13#,
            16#05#, 16#53#, 16#61#, 16#6c#, 16#65#, 16#73#, 16#31#, 16#1d#,
            16#30#, 16#1b#, 16#06#, 16#03#, 16#55#, 16#04#, 16#03#, 16#14#,
            16#14#, 16#61#, 16#6c#, 16#69#, 16#63#, 16#65#, 16#40#, 16#73#,
            16#74#, 16#72#, 16#6f#, 16#6e#, 16#67#, 16#73#, 16#77#, 16#61#,
            16#6e#, 16#2e#, 16#6f#, 16#72#, 16#67#, others => 0));
   --  Local ID: C=CH, O=Linux strongSwan, OU=Sales, CN=alice@strongswan.org.

   Remote_Id : constant Tkmrpc.Types.Idx_Type
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

end Tkm.Config;
