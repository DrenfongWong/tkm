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

      Bn_One    : Mpz_T;
      Bn_Value  : Mpz_T;
      Nil       : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      One1      : Tkmrpc.Types.Byte_Sequence (1 .. 1);
      One2      : Tkmrpc.Types.Byte_Sequence (1 .. 3);
      Value     : Tkmrpc.Types.Byte_Sequence (1 .. 5);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence (1 .. 5)
        := (0, 16#14#, 16#96#, 16#ec#, 16#d0#);
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

      Mpz_Init_Set_Ui (Rop => Bn_Value,
                       Op  => 345435344);
      Utils.To_Bytes (Bignum => Bn_Value,
                      Bytes  => Value);
      Assert (Condition => Value = Ref_Value,
              Message   => "Value mismatch");

      begin
         Utils.To_Bytes (Bignum => Bn_One,
                         Bytes  => Nil);
         Fail (Message => "Exception expected");

      exception
         when Utils.Conversion_Error => null;
      end;

      Mpz_Clear (Integer => Bn_One);
      Mpz_Clear (Integer => Bn_Value);

   exception
      when others =>
         Mpz_Clear (Integer => Bn_One);
         Mpz_Clear (Integer => Bn_Value);
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

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Util tests");
      T.Add_Test_Routine
        (Routine => Convert_Byte_Sequence_To_Hex'Access,
         Name    => "Convert byte sequence to hex string");
      T.Add_Test_Routine
        (Routine => Convert_Bignum_To_Bytes'Access,
         Name    => "Convert bignum to byte sequence");
   end Initialize;

end Util_Tests;
