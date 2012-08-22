with Tkm.Utils;

package body Tkm.Crypto.Hmac
is

   -------------------------------------------------------------------------

   function Generate
     (Ctx  : in out Context_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
   begin

      --  H(K XOR opad, H(K XOR ipad, data))

      Update (Ctx   => Ctx.Hasher,
              Input => Utils.To_String (Input => Data));

      declare
         Buffer : constant String := Digest (Ctx => Ctx.Hasher);
         Hash   : Hash_Ctx_Type   := Initial_Ctx;
      begin
         Update (Ctx   => Hash,
                 Input => Utils.To_String (Input => Ctx.Opaded_Key));
         Update (Ctx   => Hash,
                 Input => Utils.To_String
                   (Input => Utils.To_Bytes
                      (Input => Buffer)));

         --  Reinit for next call

         Ctx.Hasher := Initial_Ctx;
         Update (Ctx   => Ctx.Hasher,
                 Input => Utils.To_String (Input => Ctx.Ipaded_Key));

         return Utils.To_Bytes (Input => Digest (Ctx => Hash));
      end;
   end Generate;

   -------------------------------------------------------------------------

   procedure Init
     (Ctx : in out Context_Type;
      Key :        Tkmrpc.Types.Byte_Sequence)
   is
      use type Tkmrpc.Types.Byte;

      Buffer : Tkmrpc.Types.Byte_Sequence (Ctx.Ipaded_Key'Range)
        := (others => 0);
   begin
      if Key'Length > Buffer'Length then

         --  Hash key if it is too long

         declare
            H : Hash_Ctx_Type := Initial_Ctx;
         begin
            Update (Ctx   => H,
                    Input => Utils.To_String (Input => Key));
            Buffer (1 .. Hash_Length) := Utils.To_Bytes
              (Input => Digest (Ctx => H));
         end;
      else

         --  Otherwise copy to pre-padded buffer

         Buffer (1 .. Key'Length) := Key;
      end if;

      for I in Positive range 1 .. Hash_Block_Size loop
         Ctx.Ipaded_Key (I) := Buffer (I) xor 16#36#;
         Ctx.Opaded_Key (I) := Buffer (I) xor 16#5c#;
      end loop;

      Update (Ctx   => Ctx.Hasher,
              Input => Utils.To_String (Input => Ctx.Ipaded_Key));
   end Init;

end Tkm.Crypto.Hmac;
