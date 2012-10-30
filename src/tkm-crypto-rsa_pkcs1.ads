with Ada.Finalization;

with GMP.Binding;

generic

   type Hash_Ctx_Type is private;
   --  Associated hasher context.

   Initial_Ctx : Hash_Ctx_Type;

   with procedure Update
     (Ctx   : in out Hash_Ctx_Type;
      Input :        String);
   --  Hasher update procedure.

   with function Digest (Ctx : Hash_Ctx_Type) return String;
   --  Hasher digest function.

package Tkm.Crypto.Rsa_Pkcs1
is

   type Signer_Type is private;
   --  Signer context.

   procedure Init
     (Ctx   : in out Signer_Type;
      N     :        String;
      E     :        String;
      D     :        String;
      P     :        String;
      Q     :        String;
      Exp1  :        String;
      Exp2  :        String;
      Coeff :        String);
   --  Initialize signer context with given private key parameters. The key
   --  parameters are expected to be in hexadecimal representation.

   function Generate
     (Ctx  : in out Signer_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  Generate RSASSA-PKCS1-v1_5 signature over given data bytes.

   Signer_Error : exception;

private

   type Signer_Type is new Ada.Finalization.Controlled with record
      Hasher : Hash_Ctx_Type := Initial_Ctx;

      K : Natural := 0;
      --  Length in octets of the RSA modulus n.

      N, E, D, P, Q, Exp1, Exp2, Coeff : GMP.Binding.Mpz_T;
   end record;

   overriding
   procedure Finalize (Ctx : in out Signer_Type);

end Tkm.Crypto.Rsa_Pkcs1;
