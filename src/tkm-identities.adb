package body Tkm.Identities
is

   ID_Payload_Hdr : constant Tkmrpc.Types.Byte_Sequence := (3, 0, 0, 0);
   --  IKE ID payload header, see RFC 5996, section 3.5.

   -------------------------------------------------------------------------

   function Encode
     (Identity : Tkmrpc.Types.Identity_Type)
      return Tkmrpc.Types.Identity_Type
   is
      Ident : Tkmrpc.Types.Identity_Type
        := (Size => Identity.Size + ID_Payload_Hdr'Length,
            Data => (others => 0));
   begin
      Ident.Data (Ident.Data'First .. ID_Payload_Hdr'Length) := ID_Payload_Hdr;
      Ident.Data (Ident.Data'First + ID_Payload_Hdr'Length .. Ident.Size)
        := Identity.Data (Identity.Data'First .. Identity.Size);
      return Ident;
   end Encode;

   -------------------------------------------------------------------------

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type
   is
      Identity : Tkmrpc.Types.Identity_Type
        := (Size => Str'Length,
            Data => (others => 0));
   begin
      for I in Str'Range loop
         Identity.Data (I) := Character'Pos (Str (I));
      end loop;

      return Identity;
   end To_Identity;

end Tkm.Identities;
