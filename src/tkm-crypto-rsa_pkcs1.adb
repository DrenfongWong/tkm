with Interfaces.C;

with Tkm.Utils;

package body Tkm.Crypto.Rsa_Pkcs1
is

   use GMP.Binding;

   package C renames Interfaces.C;

   Sha1_Digest_Info : constant String := "3021300906052b0e03021a05000414";
   --  DER encoding T of the DigestInfo value for SHA-1.

   function Rsasp1
     (Ctx  : Context_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  PKCS#1 RSASP1 signature primitive.

   -------------------------------------------------------------------------

   procedure Finalize (Ctx : in out Context_Type)
   is
   begin
      Mpz_Clear (Integer => Ctx.N);
      Mpz_Clear (Integer => Ctx.E);
      Mpz_Clear (Integer => Ctx.D);
      Mpz_Clear (Integer => Ctx.P);
      Mpz_Clear (Integer => Ctx.Q);
      Mpz_Clear (Integer => Ctx.Exp1);
      Mpz_Clear (Integer => Ctx.Exp2);
      Mpz_Clear (Integer => Ctx.Coeff);
   end Finalize;

   -------------------------------------------------------------------------

   function Generate
     (Ctx  : in out Context_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
   begin
      if Ctx.K = 0 then
         raise Signer_Error with "Signer not initialized";
      end if;

      Ctx.Hasher := Initial_Ctx;
      Update (Ctx   => Ctx.Hasher,
              Input => Utils.To_String (Input => Data));

      declare

         --  EMSA-PKCS1-v1_5 encoded message
         --  EM = 0x00 || 0x01 || PS || 0x00 || T

         H     : constant String  := Digest (Ctx => Ctx.Hasher);
         T     : constant String  := Sha1_Digest_Info & H;
         Tlen  : constant Natural := T'Length / 2;
         Pslen : constant Integer := Ctx.K - Tlen - 3;
         Em    : Tkmrpc.Types.Byte_Sequence (1 .. Ctx.K)
           := (1      => 0,
               2      => 1,
               others => 16#ff#);
      begin
         if Ctx.K < Tlen + 11 then
            raise Signer_Error with "RSA modulus of" & Ctx.K'Img & " bytes too"
              & " short to sign DER encoded message of" & Tlen'Img & " bytes";
         end if;

         Em (3 + Pslen)            := 0;
         Em (4 + Pslen .. Em'Last) := Utils.Hex_To_Bytes (Input => T);

         return Rsasp1 (Ctx  => Ctx,
                        Data => Em);
      end;
   end Generate;

   -------------------------------------------------------------------------

   procedure Init
     (Ctx   : in out Context_Type;
      N     :        String;
      E     :        String;
      D     :        String;
      P     :        String;
      Q     :        String;
      Exp1  :        String;
      Exp2  :        String;
      Coeff :        String)
   is
      use type C.int;
      use type C.size_t;

      Res : C.int;
   begin
      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.N,
                        Str    => C.To_C (N),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize modulus";
      end if;
      Ctx.K := Positive (Mpz_Sizeinbase (Op   => Ctx.N,
                                         Base => 2) + 7) / 8;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.E,
                        Str    => C.To_C (E),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize public exponent";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.D,
                        Str    => C.To_C (D),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize private exponent";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.P,
                        Str    => C.To_C (P),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize first prime p";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.Q,
                        Str    => C.To_C (Q),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize second prime q";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.Exp1,
                        Str    => C.To_C (Exp1),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize first exponent";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.Exp2,
                        Str    => C.To_C (Exp2),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize second exponent";
      end if;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.Coeff,
                        Str    => C.To_C (Coeff),
                        Base   => 16);
      if Res /= 0 then
         raise Signer_Error with "Unable to initialize coefficient";
      end if;
   end Init;

   -------------------------------------------------------------------------

   function Rsasp1
     (Ctx  : Context_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
      use type C.int;

      Res    : C.int;
      T1, T2 : Mpz_T;
   begin
      Mpz_Init_Set_Str
        (Result => Res,
         Rop    => T1,
         Str    => C.To_C (Utils.To_Hex_String (Input => Data)),
         Base   => 16);
      if Res /= 0 then
         Mpz_Clear (Integer => T1);
         raise Signer_Error with "Unable to initialize encoded message";
      end if;
      Mpz_Init (Integer => T2);

      --  Chinese remainder algorithm

      --  m1 = c^dP mod p

      Mpz_Powm (Rop    => T2,
                Base   => T1,
                Exp    => Ctx.Exp1,
                Modulo => Ctx.P);

      --  m2 = c^dQ mod q

      Mpz_Powm (Rop    => T1,
                Base   => T1,
                Exp    => Ctx.Exp2,
                Modulo => Ctx.Q);

      --  h = qInv (m1 - m2) mod p

      Mpz_Sub (Rop => T2,
               Op1 => T2,
               Op2 => T1);
      Mpz_Mul (Rop => T2,
               Op1 => T2,
               Op2 => Ctx.Coeff);
      Mpz_Mod (R => T2,
               N => T2,
               D => Ctx.P);

      --  m = m2 + h*q

      Mpz_Mul (Rop => T2,
               Op1 => T2,
               Op2 => Ctx.Q);
      Mpz_Add (Rop => T1,
               Op1 => T1,
               Op2 => T2);
      Mpz_Clear (Integer => T2);

      return Bytes : constant Tkmrpc.Types.Byte_Sequence
        := Utils.To_Bytes (Bignum => T1)
      do
         Mpz_Clear (Integer => T1);
      end return;
   end Rsasp1;

end Tkm.Crypto.Rsa_Pkcs1;
