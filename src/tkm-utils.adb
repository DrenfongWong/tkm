with Interfaces.C;

package body Tkm.Utils
is

   Hex_Chars : constant String := "0123456789abcdef";

   Null_Byte_Sequence : constant Tkmrpc.Types.Byte_Sequence (1 .. 0)
     := (others => 0);

   ------------------------------------------------------------------------

   function To_Hex_String (Input : Tkmrpc.Types.Byte_Sequence) return String
   is
      use type Interfaces.Unsigned_8;
      use type Interfaces.C.size_t;
      use type Tkmrpc.Types.Byte_Sequence;
   begin
      if Input = Null_Byte_Sequence then
         return "0";
      end if;

      declare
         Result : String (1 .. Input'Length * 2) := (others => '0');
         Where  : Integer range Result'Range     := Result'First;
         Temp   : Interfaces.Unsigned_8;
      begin
         for Index in Input'Range loop

            --  For each word

            Temp := Interfaces.Unsigned_8 (Input (Index));
            for J in reverse 0 .. 2 - 1 loop
               Result (Where + J) := Hex_Chars (Integer (Temp and 16#F#) + 1);
               Temp := Interfaces.Shift_Right (Value  => Temp,
                                               Amount => 4);
            end loop;

            if Index /= Input'Last then
               exit when Where + 2 >= Result'Last;
               Where := Where + 2;
            end if;
         end loop;

         return Result;
      end;
   end To_Hex_String;

end Tkm.Utils;
