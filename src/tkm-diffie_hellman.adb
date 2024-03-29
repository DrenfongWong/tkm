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

with System;

with Interfaces.C;

with GMP.Binding;

with Tkm.Logger;
with Tkm.Utils;

package body Tkm.Diffie_Hellman
is

   use GMP.Binding;

   package L renames Tkm.Logger;

   Modp_4096_Prime : constant String := "ffffffffffffffffc90fdaa22168c234c4c66"
     & "28b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3"
     & "a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0"
     & "bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb"
     & "8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f35620855"
     & "2bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39"
     & "e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497ce"
     & "a956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba6"
     & "4ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c9"
     & "4e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177"
     & "b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4"
     & "b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a94683"
     & "4b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc"
     & "05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd00"
     & "69127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199fffffffff"
     & "fffffff";

   Modp_3072_Prime : constant String := "ffffffffffffffffc90fdaa22168c234c4c66"
     & "28b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3"
     & "a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0"
     & "bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb"
     & "8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f35620855"
     & "2bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39"
     & "e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497ce"
     & "a956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba6"
     & "4ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c9"
     & "4e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177"
     & "b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4"
     & "b82d120a93ad2caffffffffffffffff";

   function To_Bignum
     (Bytes : Tkmrpc.Types.Byte_Sequence)
      return GMP.Binding.Mpz_T;
   --  Convert given byte sequence to GMP bignum.

   function Get_Prime (Dha_Id : Tkmrpc.Types.Dh_Algorithm_Type) return String;
   --  Get hex-string representation for prime of given Diffie-Hellman
   --  algorithm specified by id.

   -------------------------------------------------------------------------

   procedure Compute_Xa_Ya
     (Dha_Id       :     Tkmrpc.Types.Dh_Algorithm_Type;
      Random_Bytes :     Tkmrpc.Types.Byte_Sequence;
      Xa           : out Tkmrpc.Types.Byte_Sequence;
      Ya           : out Tkmrpc.Types.Byte_Sequence)
   is
      use type Interfaces.C.int;
      use type Interfaces.C.unsigned_long;

      Res                      : Interfaces.C.int;
      Bn_G, Bn_P, Bn_Xa, Bn_Ya : Mpz_T;
   begin
      Mpz_Init_Set_Str
        (Result => Res,
         Rop    => Bn_P,
         Str    => Interfaces.C.To_C (Get_Prime (Dha_Id => Dha_Id)),
         Base   => 16);
      if Res /= 0 then
         raise DH_Error with "Could not initialize group prime";
      end if;

      Bn_Xa := To_Bignum (Bytes => Random_Bytes);

      --  Assert bitsize (xa) < bitsize (group prime)

      Mpz_Clrbit (Rop       => Bn_Xa,
                  Bit_Index => Random_Bytes'Length * 8 - 1);
      L.Log (Message => "Bitsize of DH secret exponent is" & Mpz_Sizeinbase
             (Op   => Bn_Xa,
              Base => 2)'Img);

      Mpz_Init_Set_Ui (Rop => Bn_G,
                       Op  => 2);

      Mpz_Init (Bn_Ya);

      --  ya = g^xa mod p

      Mpz_Powm (Rop    => Bn_Ya,
                Base   => Bn_G,
                Exp    => Bn_Xa,
                Modulo => Bn_P);

      Utils.To_Bytes (Bignum => Bn_Xa,
                      Bytes  => Xa);
      Utils.To_Bytes (Bignum => Bn_Ya,
                      Bytes  => Ya);

      Mpz_Clear (Bn_P);
      Mpz_Clear (Bn_G);
      Mpz_Clear (Bn_Xa);
      Mpz_Clear (Bn_Ya);
   end Compute_Xa_Ya;

   -------------------------------------------------------------------------

   procedure Compute_Zz
     (Dha_Id :     Tkmrpc.Types.Dh_Algorithm_Type;
      Xa     :     Tkmrpc.Types.Byte_Sequence;
      Yb     :     Tkmrpc.Types.Byte_Sequence;
      Zz     : out Tkmrpc.Types.Byte_Sequence)
   is
      use type Interfaces.C.int;

      Res                       : Interfaces.C.int;
      Bn_P, Bn_Xa, Bn_Yb, Bn_Zz : Mpz_T;
   begin
      Mpz_Init_Set_Str
        (Result => Res,
         Rop    => Bn_P,
         Str    => Interfaces.C.To_C (Get_Prime (Dha_Id => Dha_Id)),
         Base   => 16);
      if Res /= 0 then
         raise DH_Error with "Could not initialize group prime";
      end if;

      Bn_Yb := To_Bignum (Bytes => Yb);

      --  Public value must be larger than 1

      if Mpz_Cmp_Ui (Op1 => Bn_Yb,
                     Op2 => 1) <= 0
      then
         Mpz_Clear (Bn_P);
         Mpz_Clear (Bn_Yb);
         raise DH_Error with "Other public value smaller or equal to 1";
      end if;

      --  Public value Yb must be smaller than modulus

      if Mpz_Cmp (Op1 => Bn_Yb,
                  Op2 => Bn_P) >= 0
      then
         Mpz_Clear (Bn_P);
         Mpz_Clear (Bn_Yb);
         raise DH_Error with "Other public value larger or equal to modulus";
      end if;

      Bn_Xa := To_Bignum (Bytes => Xa);

      Mpz_Init (Bn_Zz);

      --  zz = yb^xa mod p

      Mpz_Powm (Rop    => Bn_Zz,
                Base   => Bn_Yb,
                Exp    => Bn_Xa,
                Modulo => Bn_P);

      Utils.To_Bytes (Bignum => Bn_Zz,
                      Bytes  => Zz);

      Mpz_Clear (Bn_P);
      Mpz_Clear (Bn_Xa);
      Mpz_Clear (Bn_Yb);
      Mpz_Clear (Bn_Zz);
   end Compute_Zz;

   -------------------------------------------------------------------------

   function Get_Group_Size
     (Dha_Id : Tkmrpc.Types.Dh_Algorithm_Type)
      return Tkmrpc.Types.Byte_Sequence_Range
   is
   begin

      --  The group size is equal to the length of the hex-string prime divided
      --  by 2

      return Get_Prime (Dha_Id => Dha_Id)'Length / 2;
   end Get_Group_Size;

   -------------------------------------------------------------------------

   function Get_Prime (Dha_Id : Tkmrpc.Types.Dh_Algorithm_Type) return String
   is
   begin
      case Dha_Id is
         when Dha_Modp_3072 => return Modp_3072_Prime;
         when Dha_Modp_4096 => return Modp_4096_Prime;
         when others =>
            raise DH_Error with "Unsupported DH algorithm" & Dha_Id'Img;
      end case;
   end Get_Prime;

   -------------------------------------------------------------------------

   function To_Bignum
     (Bytes : Tkmrpc.Types.Byte_Sequence)
      return GMP.Binding.Mpz_T
   is
      procedure Mpz_Import
        (Rop    : in out GMP.Binding.Mpz_T;
         Count  :        Interfaces.C.size_t;
         Order  :        Interfaces.C.int;
         Size   :        Interfaces.C.size_t;
         Endian :        Interfaces.C.int;
         Nails  :        Interfaces.C.size_t;
         Op     :        System.Address);
      pragma Import (C, Mpz_Import, "__gmpz_import");

      Bignum : Mpz_T;
   begin
      Mpz_Init (Bignum);
      Mpz_Import (Rop    => Bignum,
                  Count  => Bytes'Length,
                  Order  => 1,
                  Size   => 1,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Bytes'Address);

      return Bignum;
   end To_Bignum;

end Tkm.Diffie_Hellman;
