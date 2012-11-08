package Tkm.Config
is

   Pre_Shared_Key : constant String := "foobar";
   --  Pre-shared key used for (PSK) authentification.

   Local_Addr : constant String := "152.96.15.32";
   --  ESP source address.

   Peer_Addr : constant String := "152.96.15.60";
   --  ESP destination address.

   Local_Id : constant Tkmrpc.Types.Idx_Type
     := (Size => 24,
         Data =>
           (16#03#, 16#00#, 16#00#, 16#00#, 16#61#, 16#6C#, 16#69#, 16#63#,
            16#65#, 16#40#, 16#73#, 16#74#, 16#72#, 16#6F#, 16#6E#, 16#67#,
            16#73#, 16#77#, 16#61#, 16#6E#, 16#2E#, 16#6F#, 16#72#, 16#67#,
            others => 0));
   --  Local ID: alice@strongswan.org.

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
