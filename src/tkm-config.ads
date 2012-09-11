package Tkm.Config
is

   Pre_Shared_Key : constant String := "foobar";
   --  Pre-shared key used for (PSK) authentification.

   Local_Addr : constant String := "152.96.15.32";
   --  ESP source address.

   Peer_Addr : constant String := "152.96.15.60";
   --  ESP destination address.

   Lifetime : constant := 3600;
   --  ESP SA lifetime in seconds.

end Tkm.Config;
