package body Tkm.Identities
is

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

end Tkm.Identities;
