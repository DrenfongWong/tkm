with System;

with Interfaces.C;

package body Tkm.Utils
is

   Hex_Chars : constant String := "0123456789abcdef";

   Null_Byte_Sequence : constant Tkmrpc.Types.Byte_Sequence (1 .. 0)
     := (others => 0);

   -------------------------------------------------------------------------

   procedure To_Bytes
     (Bignum :     GMP.Binding.Mpz_T;
      Bytes  : out Tkmrpc.Types.Byte_Sequence)
   is
      use GMP.Binding;
      use type Interfaces.C.size_t;

      procedure Mpz_Export
        (Result : out System.Address;
         Rop    :     System.Address;
         Countp :     Interfaces.C.size_t;
         Order  :     Interfaces.C.int;
         Size   :     Interfaces.C.size_t;
         Endian :     Interfaces.C.int;
         Nails  :     Interfaces.C.size_t;
         Op     :     GMP.Binding.Mpz_T);
      pragma Import (C, Mpz_Export, "__gmpz_export");
      pragma Import_Valued_Procedure (Mpz_Export);

      procedure C_Free (Ptr : System.Address);
      pragma Import (C, C_Free, "free");

      Addr : System.Address := System.Null_Address;
      Bits : constant Interfaces.C.size_t
        := Mpz_Sizeinbase
          (Op   => Bignum,
           Base => 2);
      Size : constant Interfaces.C.size_t
        := Interfaces.C.size_t (Float'Ceiling (Float (Bits) / 8.0));
   begin
      if Integer (Size) > Bytes'Last then
         raise Conversion_Error with "Unable to convert bignum to bytes, "
           & "sequence size" & Bytes'Last'Img & " smaller than needed ("
           & Size'Img & " )";
      end if;

      Mpz_Export (Result => Addr,
                  Rop    => System.Null_Address,
                  Countp => 0,
                  Order  => 1,
                  Size   => Size,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Bignum);

      declare
         Byte_Seq : Tkmrpc.Types.Byte_Sequence (1 .. Integer (Size));
         for Byte_Seq'Address use Addr;
      begin
         Bytes := (others => 0);
         Bytes (Bytes'Last - Byte_Seq'Last + 1 .. Bytes'Last) := Byte_Seq;
         C_Free (Ptr => Addr);
      end;
   end To_Bytes;

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
