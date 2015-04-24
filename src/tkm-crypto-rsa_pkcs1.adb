--
--  Copyright (C) 2013  Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2013  Adrian-Ken Rueegsegger <ken@codelabs.ch>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

with Interfaces.C;

with Tkm.Utils;

package body Tkm.Crypto.Rsa_Pkcs1
is

   use GMP.Binding;

   package C renames Interfaces.C;

   function Emsa_Encode
     (Size : Positive;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  Encodes the given data with EMSA-PKCS1-v1_5 format. The Size argument
   --  specifies the size of the resulting encoded message (which is normally
   --  the size of the modulus in bytes).

   function Rsasp1
     (Ctx  : Signer_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  PKCS#1 RSASP1 signature primitive.

   function Rsavp1
     (Ctx  : Verifier_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  PKCS#1 RSAVP1 signature primitive.

   -------------------------------------------------------------------------

   function Emsa_Encode
     (Size : Positive;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
      Hasher : Hash_Ctx_Type := Initial_Ctx;
   begin
      Update (Ctx   => Hasher,
              Input => Utils.To_String (Input => Data));

      declare
         use type Tkmrpc.Types.Byte_Sequence;

         --  EMSA-PKCS1-v1_5 encoded message
         --  EM = 0x00 || 0x01 || PS || 0x00 || T

         H     : constant String  := Digest (Ctx => Hasher);
         T     : constant String  := Digest_Info & H;
         Tlen  : constant Natural := T'Length / 2;
         Pslen : constant Integer := Size - Tlen - 3;
         Em    : Tkmrpc.Types.Byte_Sequence (1 .. Size)
           := (1      => 0,
               2      => 1,
               others => 16#ff#);
      begin
         if Size < Tlen + 11 then
            raise Encoding_Error with "RSA modulus of" & Size'Img
              & " bytes too short to verify DER encoded message of"
              & Tlen'Img & " bytes";
         end if;

         Em (3 + Pslen)            := 0;
         Em (4 + Pslen .. Em'Last) := Utils.Hex_To_Bytes (Input => T);
         return Em;
      end;
   end Emsa_Encode;

   -------------------------------------------------------------------------

   procedure Finalize (Ctx : in out Signer_Type)
   is
   begin
      Mpz_Clear (Ctx.N);
      Mpz_Clear (Ctx.E);
      Mpz_Clear (Ctx.D);
      Mpz_Clear (Ctx.P);
      Mpz_Clear (Ctx.Q);
      Mpz_Clear (Ctx.Exp1);
      Mpz_Clear (Ctx.Exp2);
      Mpz_Clear (Ctx.Coeff);
   end Finalize;

   -------------------------------------------------------------------------

   procedure Finalize (Ctx : in out Verifier_Type)
   is
   begin
      Mpz_Clear (Ctx.N);
      Mpz_Clear (Ctx.E);
   end Finalize;

   -------------------------------------------------------------------------

   function Generate
     (Ctx  : Signer_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
   begin
      if Ctx.K = 0 then
         raise Signer_Error with "Signer not initialized";
      end if;

      return Rsasp1
        (Ctx  => Ctx,
         Data => Emsa_Encode
           (Size => Ctx.K,
            Data => Data));
   end Generate;

   -------------------------------------------------------------------------

   procedure Init
     (Ctx   : out Signer_Type;
      N     :     String;
      E     :     String;
      D     :     String;
      P     :     String;
      Q     :     String;
      Exp1  :     String;
      Exp2  :     String;
      Coeff :     String)
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

   procedure Init
     (Ctx   : out Verifier_Type;
      N     :     String;
      E     :     String)
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
         raise Verifier_Error with "Unable to initialize modulus";
      end if;
      Ctx.K := Positive (Mpz_Sizeinbase (Op   => Ctx.N,
                                         Base => 2) + 7) / 8;

      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Ctx.E,
                        Str    => C.To_C (E),
                        Base   => 16);
      if Res /= 0 then
         raise Verifier_Error with "Unable to initialize public exponent";
      end if;
   end Init;

   -------------------------------------------------------------------------

   function Rsasp1
     (Ctx  : Signer_Type;
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
         Mpz_Clear (T1);
         raise Signer_Error with "Unable to initialize encoded message";
      end if;
      Mpz_Init (T2);

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
      Mpz_Clear (T2);

      return Bytes : constant Tkmrpc.Types.Byte_Sequence
        := Utils.To_Bytes (Bignum => T1)
      do
         Mpz_Clear (T1);
      end return;
   end Rsasp1;

   -------------------------------------------------------------------------

   function Rsavp1
     (Ctx  : Verifier_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
      use type C.int;

      Res  : C.int;
      S, M : Mpz_T;
   begin
      Mpz_Init_Set_Str
        (Result => Res,
         Rop    => S,
         Str    => C.To_C (Utils.To_Hex_String (Input => Data)),
         Base   => 16);
      if Res /= 0 then
         Mpz_Clear (S);
         raise Verifier_Error with "Unable to initialize signature";
      end if;

      Mpz_Init (M);
      Mpz_Powm (Rop    => M,
                Base   => S,
                Exp    => Ctx.E,
                Modulo => Ctx.N);
      Mpz_Clear (S);

      declare
         Bytes  : constant Tkmrpc.Types.Byte_Sequence
           := Utils.To_Bytes (Bignum => M);
         Result : Tkmrpc.Types.Byte_Sequence (1 .. Ctx.K) := (others => 0);
      begin
         Result ((Result'Last - Bytes'Last + 1) .. Result'Last) := Bytes;
         Mpz_Clear (M);
         return Result;
      end;
   end Rsavp1;

   -------------------------------------------------------------------------

   function Verify
     (Ctx       : Verifier_Type;
      Data      : Tkmrpc.Types.Byte_Sequence;
      Signature : Tkmrpc.Types.Byte_Sequence)
      return Boolean
   is
   begin
      if Ctx.K = 0 then
         raise Verifier_Error with "Verifier not initialized";
      end if;

      if Signature'Length = 0 or else Signature'Length > Ctx.K then
         raise Verifier_Error with "Invalid signature length:"
           & Signature'Length'Img & ", modulus is" & Ctx.K'Img & " bytes";
      end if;

      declare
         use type Tkmrpc.Types.Byte_Sequence;

         Message : constant Tkmrpc.Types.Byte_Sequence := Rsavp1
           (Ctx  => Ctx,
            Data => Signature);
      begin
         if Emsa_Encode (Size => Ctx.K,
                         Data => Data) = Message
         then
            return True;
         end if;
      end;

      return False;
   end Verify;

end Tkm.Crypto.Rsa_Pkcs1;
