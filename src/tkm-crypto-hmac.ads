with Tkmrpc.Types;

generic

   Hash_Block_Size : Positive;
   --  Block size used by the associated hasher.

   Hash_Length : Positive;
   --  Hash output length of associated hasher.

   type Hash_Ctx_Type is private;
   --  Associated hasher context.

   Initial_Ctx : Hash_Ctx_Type;

   with procedure Update
     (Ctx   : in out Hash_Ctx_Type;
      Input :        String);
   --  Hasher update procedure.

   with function Digest (Ctx : Hash_Ctx_Type) return String;
   --  Hasher digest function.

package Tkm.Crypto.Hmac
is

   type Context_Type is private;
   --  HMAC context.

   procedure Init
     (Ctx : in out Context_Type;
      Key :        Tkmrpc.Types.Byte_Sequence);
   --  Initialize HMAC context with given key.

   function Generate
     (Ctx  : in out Context_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  Generate MAC for given data bytes.

private

   type Context_Type is record
      Hasher     : Hash_Ctx_Type := Initial_Ctx;
      Ipaded_Key : Tkmrpc.Types.Byte_Sequence (1 .. Hash_Block_Size);
      Opaded_Key : Tkmrpc.Types.Byte_Sequence (1 .. Hash_Block_Size);
   end record;

end Tkm.Crypto.Hmac;
