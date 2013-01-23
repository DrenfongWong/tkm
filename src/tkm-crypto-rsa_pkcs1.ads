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

with Ada.Finalization;

with GMP.Binding;

generic

   type Hash_Ctx_Type is private;
   --  Associated hasher context.

   Initial_Ctx : Hash_Ctx_Type;
   --  Initial hash context.

   Digest_Info : String;
   --  DER encoding of the DigestInfo value for the associated hash algorithm
   --  (see Tkm.Digests package).

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
     (Ctx   : out Signer_Type;
      N     :     String;
      E     :     String;
      D     :     String;
      P     :     String;
      Q     :     String;
      Exp1  :     String;
      Exp2  :     String;
      Coeff :     String);
   --  Initialize signer context with given private key parameters. The key
   --  parameters are expected to be in hexadecimal representation.

   function Generate
     (Ctx  : Signer_Type;
      Data : Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  Generate RSASSA-PKCS1-v1_5 signature over given data bytes.

   type Verifier_Type is private;
   --  Verifier context.

   procedure Init
     (Ctx : out Verifier_Type;
      N   :     String;
      E   :     String);
   --  Initialize verifier context with given public key parameters. The key
   --  parameters are expected to be in hexadecimal representation.

   function Verify
     (Ctx       : Verifier_Type;
      Data      : Tkmrpc.Types.Byte_Sequence;
      Signature : Tkmrpc.Types.Byte_Sequence)
      return Boolean;
   --  Verify given RSASSA-PKCS1-v1_5 signature.

   Encoding_Error : exception;
   Signer_Error   : exception;
   Verifier_Error : exception;

private

   type Signer_Type is new Ada.Finalization.Controlled with record
      K : Natural := 0;
      --  Length in octets of the RSA modulus n.

      N, E, D, P, Q, Exp1, Exp2, Coeff : GMP.Binding.Mpz_T;
   end record;

   overriding
   procedure Finalize (Ctx : in out Signer_Type);

   type Verifier_Type is new Ada.Finalization.Controlled with record
      K : Natural := 0;
      --  Length in octets of the RSA modulus n.

      N, E : GMP.Binding.Mpz_T;
   end record;

   overriding
   procedure Finalize (Ctx : in out Verifier_Type);

end Tkm.Crypto.Rsa_Pkcs1;
