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

with Interfaces;

with GMP.Binding;

with Tkmrpc.Types;

with Tkm.Utils;

package body Util_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Convert_Bignum_To_Bytes
   is
      use GMP.Binding;
      use type Tkmrpc.Types.Byte_Sequence;

      Bn_One     : Mpz_T;
      Bn_Value1  : Mpz_T;
      Bn_Value2  : Mpz_T;
      Nil        : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      One1       : Tkmrpc.Types.Byte_Sequence (1 .. 1);
      One2       : Tkmrpc.Types.Byte_Sequence (1 .. 3);
      Value1     : Tkmrpc.Types.Byte_Sequence (1 .. 5);
      Value2     : Tkmrpc.Types.Byte_Sequence (1 .. 2);
      Ref_Value1 : constant Tkmrpc.Types.Byte_Sequence (1 .. 5)
        := (0, 16#14#, 16#96#, 16#ec#, 16#d0#);
      Ref_Value2 : constant Tkmrpc.Types.Byte_Sequence (1 .. 2)
        := (16#07#, 16#e3#);
   begin
      Mpz_Init_Set_Ui (Rop => Bn_One,
                       Op  => 1);
      Utils.To_Bytes (Bignum => Bn_One,
                      Bytes  => One1);
      Assert (Condition => One1 = (1 => 1),
              Message   => "One mismatch (1)");

      Utils.To_Bytes (Bignum => Bn_One,
                      Bytes  => One2);
      Assert (Condition => One2 = (0, 0, 1),
              Message   => "One mismatch (2)");

      Mpz_Init_Set_Ui (Rop => Bn_Value1,
                       Op  => 345435344);
      Utils.To_Bytes (Bignum => Bn_Value1,
                      Bytes  => Value1);
      Assert (Condition => Value1 = Ref_Value1,
              Message   => "Value mismatch (1)");

      Mpz_Init_Set_Ui (Rop => Bn_Value2,
                       Op  => 2019);
      Utils.To_Bytes (Bignum => Bn_Value2,
                      Bytes  => Value2);
      Assert (Condition => Value2 = Ref_Value2,
              Message   => "Value mismatch (2,p)");
      Assert (Condition => Utils.To_Bytes (Bignum => Bn_Value2) = Ref_Value2,
              Message   => "Value mismatch (2,f)");

      begin
         Utils.To_Bytes (Bignum => Bn_One,
                         Bytes  => Nil);
         Fail (Message => "Exception expected");

      exception
         when Utils.Conversion_Error => null;
      end;

      Mpz_Clear (Bn_One);
      Mpz_Clear (Bn_Value1);
      Mpz_Clear (Bn_Value2);

   exception
      when others =>
         Mpz_Clear (Bn_One);
         Mpz_Clear (Bn_Value1);
         Mpz_Clear (Bn_Value2);
         raise;
   end Convert_Bignum_To_Bytes;

   -------------------------------------------------------------------------

   procedure Convert_Byte_Sequence_To_Hex
   is
      Null_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      One_Byte   : constant Tkmrpc.Types.Byte_Sequence (1 .. 1)
        := (1 => 16#02#);
      Bytes      : constant Tkmrpc.Types.Byte_Sequence
        := (16#52#, 16#41#, 16#06#, 16#be#, 16#6a#, 16#65#, 16#0a#, 16#9c#);
   begin
      Assert (Condition => Utils.To_Hex_String (Input => Null_Bytes) = "0",
              Message   => "Null bytes mismatch");
      Assert (Condition => Utils.To_Hex_String (Input => One_Byte) = "02",
              Message   => "One byte mismatch");
      Assert (Condition => Utils.To_Hex_String
              (Input => Bytes) = "524106be6a650a9c",
              Message   => "Bytes mismatch");
   end Convert_Byte_Sequence_To_Hex;

   -------------------------------------------------------------------------

   procedure Convert_Bytes_To_String
   is
      Empty : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      Idx   : constant Tkmrpc.Types.Byte_Sequence (5 .. 7) := (others => 65);
   begin
      Assert (Condition => Utils.To_String
              (Input => (65, 66, 67, 68, 69)) = "ABCDE",
              Message   => "String 1 mismatch");
      Assert (Condition => Utils.To_String (Input => Empty) = "",
              Message   => "String 2 mismatch");
      Assert (Condition => Utils.To_String (Input => Idx) = "AAA",
              Message   => "String 3 mismatch");
   end Convert_Bytes_To_String;

   -------------------------------------------------------------------------

   procedure Convert_Hex_To_Bytes
   is
      use type Tkmrpc.Types.Byte_Sequence;

      Null_Bytes : constant Tkmrpc.Types.Byte_Sequence (1 .. 1)
        := (1 => 0);
      One_Byte   : constant Tkmrpc.Types.Byte_Sequence (1 .. 1)
        := (1 => 16#02#);
      Bytes      : constant Tkmrpc.Types.Byte_Sequence
        := (16#52#, 16#41#, 16#06#, 16#be#, 16#6a#, 16#65#, 16#0a#, 16#9c#);
   begin
      Assert (Condition => Utils.Hex_To_Bytes (Input => "0") = Null_Bytes,
              Message   => "Null bytes mismatch");
      Assert (Condition => Utils.Hex_To_Bytes (Input => "02") = One_Byte,
              Message   => "One byte mismatch");
      Assert (Condition => Utils.Hex_To_Bytes
              (Input => "524106be6a650a9c") = Bytes,
              Message   => "Bytes mismatch");
      begin
         declare
            Dummy : constant Tkmrpc.Types.Byte_Sequence
              := Utils.Hex_To_Bytes (Input => "zz");
            pragma Unreferenced (Dummy);
         begin
            Fail (Message => "Exception expected");
         end;

      exception
         when Utils.Conversion_Error => null;
      end;
   end Convert_Hex_To_Bytes;

   -------------------------------------------------------------------------

   procedure Convert_String_To_Bytes
   is
      use type Tkmrpc.Types.Byte_Sequence;

      Empty : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      Idx   : constant String (5 .. 7) := (others => 'A');
   begin
      Assert (Condition => Utils.To_Bytes
              (Input => "ABCDE") = (65, 66, 67, 68, 69),
              Message   => "String 1 mismatch");
      Assert (Condition => Utils.To_Bytes (Input => "") = Empty,
              Message   => "String 2 mismatch");
      Assert (Condition => Utils.To_Bytes (Input => Idx) = (65, 65, 65),
              Message   => "String 3 mismatch");
   end Convert_String_To_Bytes;

   -------------------------------------------------------------------------

   procedure Convert_U32_To_Hex
   is
      Ref_1 : constant String := "0";
      Ref_2 : constant String := "FFFFFFFF";
      Ref_3 : constant String := "2A";
      Ref_4 : constant String := "DEADBEEF";
   begin
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_32'First) = Ref_1,
              Message   => "Hex string mismatch (1)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_32'Last) = Ref_2,
              Message   => "Hex string mismatch (2)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_32'(42)) = Ref_3,
              Message   => "Hex string mismatch (3)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_32'(3735928559)) = Ref_4,
              Message   => "Hex string mismatch (4)");
   end Convert_U32_To_Hex;

   -------------------------------------------------------------------------

   procedure Convert_U64_To_Bytes
   is
      use type Tkmrpc.Types.Byte_Sequence;

      Ref_Seq1 : constant Tkmrpc.Types.Byte_Sequence (1 .. 8)
        := (others => 0);
      Ref_Seq2 : constant Tkmrpc.Types.Byte_Sequence (1 .. 8)
        := (others => 255);
      Ref_Seq3 : constant Tkmrpc.Types.Byte_Sequence (1 .. 8)
        := (16#28#, 16#04#, 16#44#, others => 0);
      Ref_Seq4 : constant Tkmrpc.Types.Byte_Sequence (1 .. 8)
        := (16#5b#, 16#3a#, 16#66#, 16#5c#, 16#32#, 16#51#, 16#95#, 16#98#);
   begin
      Assert (Condition => Utils.To_Bytes (Input => 0) = Ref_Seq1,
              Message   => "Bytes mismatch (1)");
      Assert (Condition => Utils.To_Bytes
              (Input => Interfaces.Unsigned_64'Last) = Ref_Seq2,
              Message   => "Bytes mismatch (2)");
      Assert (Condition => Utils.To_Bytes
              (Input => 4457512) = Ref_Seq3,
              Message   => "Bytes mismatch (3)");
      Assert (Condition => Utils.To_Bytes
              (Input => 10994783342035352155) = Ref_Seq4,
              Message   => "Bytes mismatch (4)");
   end Convert_U64_To_Bytes;

   -------------------------------------------------------------------------

   procedure Convert_U64_To_Hex
   is
      Ref_1 : constant String := "0";
      Ref_2 : constant String := "FFFFFFFFFFFFFFFF";
      Ref_3 : constant String := "2A";
      Ref_4 : constant String := "DEADBEEFDEADBEEF";
   begin
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_64'First) = Ref_1,
              Message   => "Hex string mismatch (1)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_64'Last) = Ref_2,
              Message   => "Hex string mismatch (2)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_64'(42)) = Ref_3,
              Message   => "Hex string mismatch (3)");
      Assert (Condition => Utils.To_Hex_String
              (Input => Interfaces.Unsigned_64'(16045690984833335023)) = Ref_4,
              Message   => "Hex string mismatch (4)");
   end Convert_U64_To_Hex;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Util tests");
      T.Add_Test_Routine
        (Routine => Convert_Bytes_To_String'Access,
         Name    => "Convert bytes to string");
      T.Add_Test_Routine
        (Routine => Convert_Byte_Sequence_To_Hex'Access,
         Name    => "Convert byte sequence to hex string");
      T.Add_Test_Routine
        (Routine => Convert_Bignum_To_Bytes'Access,
         Name    => "Convert bignum to byte sequence");
      T.Add_Test_Routine
        (Routine => Convert_Hex_To_Bytes'Access,
         Name    => "Convert hex strings to byte sequences");
      T.Add_Test_Routine
        (Routine => Convert_U64_To_Bytes'Access,
         Name    => "Convert unsigned 64 to byte sequences");
      T.Add_Test_Routine
        (Routine => Convert_String_To_Bytes'Access,
         Name    => "Convert string to byte sequences");
      T.Add_Test_Routine
        (Routine => Convert_U32_To_Hex'Access,
         Name    => "Convert unsigned 32 to hex string");
      T.Add_Test_Routine
        (Routine => Convert_U64_To_Hex'Access,
         Name    => "Convert unsigned 64 to hex string");
   end Initialize;

end Util_Tests;
