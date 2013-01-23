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

with Tkm.Logger;
with Tkm.Crypto.Prf_Plus_Hmac_Sha512;
with Tkm.Utils;

package body Tkm.Key_Derivation
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Derive_Child_Keys
     (Sk_D    :     Tkmrpc.Types.Byte_Sequence;
      Secret  :     Tkmrpc.Types.Byte_Sequence;
      Nonce_I :     Tkmrpc.Types.Byte_Sequence;
      Nonce_R :     Tkmrpc.Types.Byte_Sequence;
      Enc_I   : out Tkmrpc.Types.Key_Type;
      Enc_R   : out Tkmrpc.Types.Key_Type;
      Int_I   : out Tkmrpc.Types.Key_Type;
      Int_R   : out Tkmrpc.Types.Key_Type)
   is
      Int_Key_Len : constant := 64;
      Enc_Key_Len : constant := 32;
      Seed_Size   : constant Positive := Secret'Length + Nonce_I'Length
        + Nonce_R'Length;
      Seed        : Tkmrpc.Types.Byte_Sequence (1 .. Seed_Size);
      Idx_Nc_I    : constant Positive := Seed'First + Secret'Length;
      Idx_Nc_R    : constant Positive := Idx_Nc_I + Nonce_I'Length;
      Prf_Plus    : Crypto.Prf_Plus_Hmac_Sha512.Context_Type;
   begin

      --  Seed = Secret | Nonce_I | Nonce_R

      Seed (Seed'First .. Idx_Nc_I - 1) := Secret;
      Seed (Idx_Nc_I  .. Idx_Nc_R - 1)  := Nonce_I;
      Seed (Idx_Nc_R .. Seed'Last)      := Nonce_R;

      L.Log (Message => "Sk_D " & Utils.To_Hex_String (Input => Sk_D));
      L.Log (Message => "Seed " & Utils.To_Hex_String (Input => Seed));

      --  KEYMAT = encr_i | integ_i | encr_r | integ_r

      Crypto.Prf_Plus_Hmac_Sha512.Init (Ctx  => Prf_Plus,
                                        Key  => Sk_D,
                                        Seed => Seed);

      --  Initiator ESP keys

      Enc_I.Data (Enc_I.Data'First .. Enc_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Enc_Key_Len);
      Enc_I.Size := Enc_Key_Len;
      Int_I.Data (Int_I.Data'First .. Int_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Int_Key_Len);
      Int_I.Size := Int_Key_Len;

      --  Responder ESP keys

      Enc_R.Data (Enc_R.Data'First .. Enc_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Enc_Key_Len);
      Enc_R.Size := Enc_Key_Len;
      Int_R.Data (Int_R.Data'First .. Int_Key_Len)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Int_Key_Len);
      Int_R.Size := Int_Key_Len;
   end Derive_Child_Keys;

   -------------------------------------------------------------------------

   procedure Derive_Ike_Keys
     (Skeyseed :     Tkmrpc.Types.Byte_Sequence;
      Prf_Seed :     Tkmrpc.Types.Byte_Sequence;
      Sk_D     : in out Tkmrpc.Types.Key_Type;
      Sk_Ai    : in out Tkmrpc.Types.Key_Type;
      Sk_Ar    : in out Tkmrpc.Types.Key_Type;
      Sk_Ei    : in out Tkmrpc.Types.Key_Type;
      Sk_Er    : in out Tkmrpc.Types.Key_Type;
      Sk_Pi    : in out Tkmrpc.Types.Key_Type;
      Sk_Pr    : in out Tkmrpc.Types.Key_Type)
   is
      Prf_Plus : Crypto.Prf_Plus_Hmac_Sha512.Context_Type;
   begin
      L.Log (Message => "SKEYSEED " & Utils.To_Hex_String
             (Input => Skeyseed));
      L.Log (Message => "PRFPLUSSEED " & Utils.To_Hex_String
             (Input => Prf_Seed));

      --  KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr

      Crypto.Prf_Plus_Hmac_Sha512.Init (Ctx  => Prf_Plus,
                                        Key  => Skeyseed,
                                        Seed => Prf_Seed);

      --  Key for derivation of further (child) key material

      Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Sk_D.Size);
      L.Log (Message => "Sk_D  " & Utils.To_Hex_String
             (Input => Sk_D.Data (Sk_D.Data'First .. Sk_D.Size)));

      --  IKE authentication keys

      Sk_Ai.Data (1 .. Sk_Ai.Size) := Crypto.Prf_Plus_Hmac_Sha512.Generate
        (Ctx    => Prf_Plus,
         Length => Sk_Ai.Size);
      Sk_Ar.Data (1 .. Sk_Ar.Size) := Crypto.Prf_Plus_Hmac_Sha512.Generate
        (Ctx    => Prf_Plus,
         Length => Sk_Ai.Size);
      L.Log (Message => "Sk_Ai " & Utils.To_Hex_String
             (Input => Sk_Ai.Data (1 .. Sk_Ai.Size)));
      L.Log (Message => "Sk_Ar " & Utils.To_Hex_String
             (Input => Sk_Ar.Data (1 .. Sk_Ar.Size)));

      --  IKE encryption keys

      Sk_Ei.Data (1 .. Sk_Ei.Size) := Crypto.Prf_Plus_Hmac_Sha512.Generate
        (Ctx    => Prf_Plus,
         Length => Sk_Ei.Size);
      Sk_Er.Data (1 .. Sk_Er.Size) := Crypto.Prf_Plus_Hmac_Sha512.Generate
        (Ctx    => Prf_Plus,
         Length => Sk_Er.Size);
      L.Log (Message => "Sk_Ei " & Utils.To_Hex_String
             (Input => Sk_Ei.Data (1 .. Sk_Ei.Size)));
      L.Log (Message => "Sk_Er " & Utils.To_Hex_String
             (Input => Sk_Er.Data (1 .. Sk_Er.Size)));

      --  Keys used for AUTH payload generation

      Sk_Pi.Data (Sk_Pi.Data'First .. Sk_Pi.Size)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Sk_Pi.Size);
      Sk_Pr.Data (Sk_Pr.Data'First .. Sk_Pr.Size)
        := Crypto.Prf_Plus_Hmac_Sha512.Generate
          (Ctx    => Prf_Plus,
           Length => Sk_Pr.Size);
      L.Log (Message => "Sk_Pi " & Utils.To_Hex_String
             (Input => Sk_Pi.Data (Sk_Pi.Data'First .. Sk_Pi.Size)));
      L.Log (Message => "Sk_Pr " & Utils.To_Hex_String
             (Input => Sk_Pr.Data (Sk_Pr.Data'First .. Sk_Pr.Size)));
   end Derive_Ike_Keys;

end Tkm.Key_Derivation;
