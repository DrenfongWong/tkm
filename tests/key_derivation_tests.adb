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

with Tkm.Key_Derivation;
with Tkm.Utils;

package body Key_Derivation_Tests
is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Derive_Child_Keys
   is
      use type Tkmrpc.Types.Byte_Sequence;

      Sk_D    : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "70e889b685ae906f3700c27f11b5633152c0cd582e989d18e54d405e84b"
         & "30b5a12c11af8c2a8228defe54e82537321a607412dee7eafc898ecce592333753"
         & "332");
      Nc_I    : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "1ad3b9306b750c153b2e0aa08ccf132569affbb6656d03151aee8bbbd02"
         & "8f0b7");
      Nc_R    : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "026cc399c78bf7cd0a2ec0cdc970a2913516f36a939daf2cbec840f2c09"
         & "f44d1");
      Ref_E_I : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "7fa67ca92f9c863778092a0e381ecc2a72af0d302a5466521b9085d3bcb"
         & "02b7d");
      Ref_E_R : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "88429bd9569148405be68f5ff94023d9edc2c1891d1361da04bd891add3"
         & "f2094");
      Ref_I_I : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "1aba5f3c7fa0336977305518d3a6d9918cd7b35c2db3f019931db875c48"
         & "50f01ee5a6a17dbe3ae5a8b73f806b701b7db419e3c5ed308b62e8c085f86a6aeb"
         & "e7a");
      Ref_I_R : constant Tkmrpc.Types.Byte_Sequence := Utils.Hex_To_Bytes
        (Input => "95faec08b38d8d36342ff4f316ca8a1efc83ed1c4693f4492f20b1ac29a"
         & "f608c8aa092e1af507a31c3f8d7857f8eb490725c4d54224eb7eb0f7bccb3b5d9b"
         & "dc9");

      E_I, E_R, I_I, I_R : Tkmrpc.Types.Key_Type := Tkmrpc.Types.Null_Key_Type;
   begin
      Key_Derivation.Derive_Child_Keys
        (Sk_D    => Sk_D,
         Secret  => Null_Byte_Sequence,
         Nonce_I => Nc_I,
         Nonce_R => Nc_R,
         Enc_I   => E_I,
         Enc_R   => E_R,
         Int_I   => I_I,
         Int_R   => I_R);

      Assert (Condition => E_I.Data (1 .. E_I.Size) = Ref_E_I,
              Message   => "Enc_I mismatch");
      Assert (Condition => E_R.Data (1 .. E_R.Size) = Ref_E_R,
              Message   => "Enc_R mismatch");
      Assert (Condition => I_I.Data (1 .. I_I.Size) = Ref_I_I,
              Message   => "Int_I mismatch");
      Assert (Condition => I_R.Data (1 .. I_R.Size) = Ref_I_R,
              Message   => "Int_R mismatch");
   end Derive_Child_Keys;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Key derivation tests");
      T.Add_Test_Routine
        (Routine => Derive_Child_Keys'Access,
         Name    => "Child key derivation");
   end Initialize;

end Key_Derivation_Tests;
