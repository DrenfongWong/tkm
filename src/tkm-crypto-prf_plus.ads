with Tkmrpc.Types;

generic

   Prf_Length : Positive;
   --  Output length of associated PRF.

   type Prf_Ctx_Type is private;
   --  Associated PRF context.

   with procedure Init
     (Ctx : in out Prf_Ctx_Type;
      Key :        Tkmrpc.Types.Byte_Sequence);
   --  PRF init procedure.

   with function Generate
     (Ctx  : in out Prf_Ctx_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  PRF generate procedure.

package Tkm.Crypto.Prf_Plus
is

   type Context_Type is private;
   --  PRF+ context.

   procedure Init
     (Ctx  : in out Context_Type;
      Key  :        Tkmrpc.Types.Byte_Sequence;
      Seed :        Tkmrpc.Types.Byte_Sequence);
   --  Initialize PRF+ context with given key and seed.

   function Generate
     (Ctx    : in out Context_Type;
      Length :        Positive)
      return Tkmrpc.Types.Byte_Sequence;
   --  Generate length bytes of pseudo-random data.

   Prf_Plus_Error : exception;

private

   Buffer_Size : constant := 1024;

   type Context_Type is record
      Prf_Context : Prf_Ctx_Type;
      --  Associated PRF context.

      Buffer      : Tkmrpc.Types.Byte_Sequence (1 .. Buffer_Size)
        := (others => 0);
      --  Buffer format: Ti | S | i
      --  (see RFC 5996, section 2.13)

      Seed_Idx    : Positive;
      --  Seed start position in buffer.

      Ctr_Idx     : Positive;
      --  Counter (i) position in buffer.

      Consumed    : Natural;
      --  Number of already consumed bytes.
   end record;

end Tkm.Crypto.Prf_Plus;
