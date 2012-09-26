package Tkm.Config
is

   Pre_Shared_Key : constant String := "foobar";
   --  Pre-shared key used for (PSK) authentification.

   Local_Addr : constant String := "152.96.15.32";
   --  ESP source address.

   Peer_Addr : constant String := "152.96.15.60";
   --  ESP destination address.

   Lifetime_Hard : constant := 60;
   --  ESP SA lifetime in seconds (hard).

   Lifetime_Soft : constant := 30;
   --  ESP SA lifetime in seconds (soft).

end Tkm.Config;
