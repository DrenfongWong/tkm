with Tkmrpc.Types;

with Tkm.Utils;

package body Util_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Convert_Byte_Sequence_To_Hex
   is
      Null_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 0);
      One_Byte   : Tkmrpc.Types.Byte_Sequence (1 .. 1) := (1 => 16#02#);
      Bytes      : constant Tkmrpc.Types.Byte_Sequence :=
        (16#52#, 16#41#, 16#06#, 16#be#, 16#6a#, 16#65#, 16#0a#, 16#9c#);
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
   end Initialize;

end Util_Tests;
