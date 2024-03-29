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

with Ada.Unchecked_Conversion;
with Ada.Text_IO;
with Ada.Strings.Fixed;

with System;

with Interfaces.C;

with GNAT.Byte_Swapping;

package body Tkm.Utils
is

   Hex_Chars : constant String := "0123456789abcdef";

   Null_Byte_Sequence : constant Tkmrpc.Types.Byte_Sequence (1 .. 0)
     := (others => 0);

   function Swapped is new
     GNAT.Byte_Swapping.Swapped4 (Item => Interfaces.Unsigned_32);

   function Bignum_Size (Integer : GMP.Binding.Mpz_T) return Natural;
   --  Return size in bytes of given bignum.

   -------------------------------------------------------------------------

   function Bignum_Size (Integer : GMP.Binding.Mpz_T) return Natural
   is
      Bits : constant Interfaces.C.size_t
        := GMP.Binding.Mpz_Sizeinbase
          (Op   => Integer,
           Base => 2);
   begin
      return (Natural (Bits) + 7) / 8;
   end Bignum_Size;

   -------------------------------------------------------------------------

   function Hex_To_Bytes (Input : String) return Tkmrpc.Types.Byte_Sequence
   is
   begin
      if Input = "" then
         return (1 => 0);
      end if;

      declare
         Result : Tkmrpc.Types.Byte_Sequence
           (1 .. Tkmrpc.Types.Byte_Sequence_Range
              (Float'Ceiling (Float (Input'Length) / 2.0)))
           := (others => 0);
      begin
         for Index in Result'Range loop
            declare
               Hex_Byte : String (1 .. 2) := "00";
            begin
               Hex_Byte (1) := Input (Index * 2 - 1);
               if Index * 2 <= Input'Last then
                  Hex_Byte (2) := Input (Index * 2);
               end if;
               Result (Index) := Tkmrpc.Types.Byte'Value
                 ("16#" & Hex_Byte & "#");
            end;
            exit when Index * 2 - 1 > Input'Last;
         end loop;

         return Result;
      end;

   exception
      when Constraint_Error =>
         raise Conversion_Error with "'" & Input & "' is not a valid hex"
           & " string";
   end Hex_To_Bytes;

   -------------------------------------------------------------------------

   function Network_To_Host
     (Input : Interfaces.Unsigned_32)
      return Interfaces.Unsigned_32
   is
      use type System.Bit_Order;
   begin
      if System.Default_Bit_Order = System.Low_Order_First then
         return Swapped (Input);
      else
         return Input;
      end if;
   end Network_To_Host;

   -------------------------------------------------------------------------

   procedure To_Bytes
     (Bignum :     GMP.Binding.Mpz_T;
      Bytes  : out Tkmrpc.Types.Byte_Sequence)
   is
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
      Size : constant Interfaces.C.size_t
        := Interfaces.C.size_t (Bignum_Size (Bignum));
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

   -------------------------------------------------------------------------

   function To_Bytes
     (Bignum : GMP.Binding.Mpz_T)
      return Tkmrpc.Types.Byte_Sequence
   is
      Result : Tkmrpc.Types.Byte_Sequence (1 .. Bignum_Size (Bignum));
   begin
      To_Bytes (Bignum => Bignum,
                Bytes  => Result);

      return Result;
   end To_Bytes;

   -------------------------------------------------------------------------

   function To_Bytes
     (Input : Interfaces.Unsigned_64)
      return Tkmrpc.Types.Byte_Sequence
   is
      subtype U64_Bytes is Tkmrpc.Types.Byte_Sequence (1 .. 8);

      function To_Bytes is new Ada.Unchecked_Conversion
        (Source => Interfaces.Unsigned_64,
         Target => U64_Bytes);

   begin
      return To_Bytes (Input);
   end To_Bytes;

   -------------------------------------------------------------------------

   function To_Bytes (Input : String) return Tkmrpc.Types.Byte_Sequence
   is
      Result   : Tkmrpc.Types.Byte_Sequence (1 .. Input'Length);
      Idx_Diff : constant Integer := Result'First - Input'First;
   begin
      for I in Result'Range loop
         Result (I) := Character'Pos (Input (I - Idx_Diff));
      end loop;

      return Result;
   end To_Bytes;

   -------------------------------------------------------------------------

   function To_Hex_String (Input : Tkmrpc.Types.Byte_Sequence) return String
   is
      use type Interfaces.Unsigned_8;
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

   -------------------------------------------------------------------------

   function To_Hex_String (Input : Interfaces.Unsigned_32) return String
   is
      package M_IO is new Ada.Text_IO.Modular_IO
        (Num => Interfaces.Unsigned_32);

      Str : String (1 .. 12);
      Left_Idx : Natural;
   begin
      M_IO.Put (To   => Str,
                Item => Input,
                Base => 16);

      --  Strip leading '16#' and trailing '#'

      Left_Idx := Ada.Strings.Fixed.Index (Source  => Str,
                                           Pattern => "#");
      return Str (Left_Idx + 1 .. 11);
   end To_Hex_String;

   -------------------------------------------------------------------------

   function To_Hex_String (Input : Interfaces.Unsigned_64) return String
   is
      package M_IO is new Ada.Text_IO.Modular_IO
        (Num => Interfaces.Unsigned_64);

      Str : String (1 .. 24);
      Left_Idx : Natural;
   begin
      M_IO.Put (To   => Str,
                Item => Input,
                Base => 16);

      --  Strip leading '16#' and trailing '#'

      Left_Idx := Ada.Strings.Fixed.Index (Source  => Str,
                                           Pattern => "#");
      return Str (Left_Idx + 1 .. 23);
   end To_Hex_String;

   -------------------------------------------------------------------------

   function To_Sequence
     (Item : X509.Byte_Array)
      return Tkmrpc.Types.Byte_Sequence
   is
      Result : Tkmrpc.Types.Byte_Sequence (Item'Range);
   begin
      for I in Result'Range loop
         Result (I) := Tkmrpc.Types.Byte (Item (I));
      end loop;

      return Result;
   end To_Sequence;

   -------------------------------------------------------------------------

   function To_String (Input : Tkmrpc.Types.Byte_Sequence) return String
   is
      Result   : String (1 .. Input'Length);
      Idx_Diff : constant Integer := Result'First - Input'First;
   begin
      for I in Result'Range loop
         Result (I) := Character'Val (Input (I - Idx_Diff));
      end loop;

      return Result;
   end To_String;

   -------------------------------------------------------------------------

   function To_X509_Bytes
     (Item : Tkmrpc.Types.Byte_Sequence)
      return X509.Byte_Array
   is
      Result : X509.Byte_Array (Item'Range);
   begin
      for I in Result'Range loop
         Result (I) := X509.Byte (Item (I));
      end loop;

      return Result;
   end To_X509_Bytes;

end Tkm.Utils;
