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

with Tkmrpc.Types;

package Tkm.Key_Derivation
is

   procedure Derive_Ike_Keys
     (Skeyseed :     Tkmrpc.Types.Byte_Sequence;
      Prf_Seed :     Tkmrpc.Types.Byte_Sequence;
      Sk_D     : in out Tkmrpc.Types.Key_Type;
      Sk_Ai    : in out Tkmrpc.Types.Key_Type;
      Sk_Ar    : in out Tkmrpc.Types.Key_Type;
      Sk_Ei    : in out Tkmrpc.Types.Key_Type;
      Sk_Er    : in out Tkmrpc.Types.Key_Type;
      Sk_Pi    : in out Tkmrpc.Types.Key_Type;
      Sk_Pr    : in out Tkmrpc.Types.Key_Type);
   --  Derive IKE pfs secret, encryption, integrity and authentication keys
   --  from given skeyseed and seed, as specified in RFC 5996, section 2.14.
   --  The length of the various Sk_* keys is specified by their Size field
   --  value.

   procedure Derive_Child_Keys
     (Sk_D    :     Tkmrpc.Types.Byte_Sequence;
      Secret  :     Tkmrpc.Types.Byte_Sequence;
      Nonce_I :     Tkmrpc.Types.Byte_Sequence;
      Nonce_R :     Tkmrpc.Types.Byte_Sequence;
      Enc_I   : out Tkmrpc.Types.Key_Type;
      Enc_R   : out Tkmrpc.Types.Key_Type;
      Int_I   : out Tkmrpc.Types.Key_Type;
      Int_R   : out Tkmrpc.Types.Key_Type);
   --  Derive encryption and integrity keys from given sk_d, DH secret and
   --  nonces, as specified in RFC 5996, section 2.17.

end Tkm.Key_Derivation;
