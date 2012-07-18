with System;

with Interfaces.C;

with GMP.Binding;

with Tkm.Logger;

package body Tkm.Diffie_Hellman
is

   use GMP.Binding;

   package L renames Tkm.Logger;

   subtype Bytes is Tkmrpc.Types.Byte_Sequence (1 .. 512);

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

   procedure Mpz_Import
     (Rop    : in out GMP.Binding.Mpz_T;
      Count  :        Interfaces.C.size_t;
      Order  :        Interfaces.C.int;
      Size   :        Interfaces.C.size_t;
      Endian :        Interfaces.C.int;
      Nails  :        Interfaces.C.size_t;
      Op     :        System.Address);
   pragma Import (C, Mpz_Import, "__gmpz_import");

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

   -------------------------------------------------------------------------

   procedure Compute_Xa_Ya
     (Random_Bytes :     Tkmrpc.Types.Byte_Sequence;
      Xa           : out Tkmrpc.Types.Byte_Sequence;
      Ya           : out Tkmrpc.Types.Byte_Sequence)
   is
      use type Interfaces.C.int;
      use type Interfaces.C.unsigned_long;

      Res                      : Interfaces.C.int;
      Xa_Addr, Ya_Addr         : System.Address := System.Null_Address;
      Bn_G, Bn_P, Bn_Xa, Bn_Ya : Mpz_T;
   begin
      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Bn_P,
                        Str    => Interfaces.C.To_C (Modp_4096_Prime),
                        Base   => 16);
      if Res /= 0 then
         raise DH_Error with "Could not initialize group prime";
      end if;

      Mpz_Init (Integer => Bn_Xa);
      Mpz_Import (Rop    => Bn_Xa,
                  Count  => Random_Bytes'Length,
                  Order  => 1,
                  Size   => 1,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Random_Bytes'Address);

      --  Assert bitsize (xa) < bitsize (group prime)

      Mpz_Clrbit (Rop       => Bn_Xa,
                  Bit_Index => Random_Bytes'Length * 8 - 1);
      L.Log (Message => "Bitsize of DH secret exponent is" & Mpz_Sizeinbase
             (Op   => Bn_Xa,
              Base => 2)'Img);

      Mpz_Init_Set_Ui (Rop => Bn_G,
                       Op  => 2);

      Mpz_Init (Integer => Bn_Ya);

      --  ya = g^xa mod p

      Mpz_Powm (Rop    => Bn_Ya,
                Base   => Bn_G,
                Exp    => Bn_Xa,
                Modulo => Bn_P);

      Mpz_Export (Result => Xa_Addr,
                  Rop    => System.Null_Address,
                  Countp => 0,
                  Order  => 1,
                  Size   => Bytes'Length,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Bn_Xa);
      Mpz_Export (Result => Ya_Addr,
                  Rop    => System.Null_Address,
                  Countp => 0,
                  Order  => 1,
                  Size   => Bytes'Length,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Bn_Ya);

      Mpz_Clear (Integer => Bn_P);
      Mpz_Clear (Integer => Bn_G);
      Mpz_Clear (Integer => Bn_Xa);
      Mpz_Clear (Integer => Bn_Ya);

      declare
         Xa_Bytes, Ya_Bytes : Bytes;
         for Xa_Bytes'Address use Xa_Addr;
         for Ya_Bytes'Address use Ya_Addr;
      begin
         Xa := Xa_Bytes;
         Ya := Ya_Bytes;
         C_Free (Ptr => Xa_Addr);
         C_Free (Ptr => Ya_Addr);
      end;
   end Compute_Xa_Ya;

   -------------------------------------------------------------------------

   procedure Compute_Zz
     (Xa    :     Tkmrpc.Types.Byte_Sequence;
      Yb    :     Tkmrpc.Types.Byte_Sequence;
      Zz    : out Tkmrpc.Types.Byte_Sequence)
   is
      use type Interfaces.C.int;

      Res                       : Interfaces.C.int;
      Zz_Addr                   : System.Address := System.Null_Address;
      Bn_P, Bn_Xa, Bn_Yb, Bn_Zz : Mpz_T;
   begin
      Mpz_Init_Set_Str (Result => Res,
                        Rop    => Bn_P,
                        Str    => Interfaces.C.To_C (Modp_4096_Prime),
                        Base   => 16);
      if Res /= 0 then
         raise DH_Error with "Could not initialize group prime";
      end if;

      Mpz_Init (Integer => Bn_Xa);
      Mpz_Init (Integer => Bn_Yb);
      Mpz_Init (Integer => Bn_Zz);

      Mpz_Import (Rop    => Bn_Xa,
                  Count  => Xa'Length,
                  Order  => 1,
                  Size   => 1,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Xa'Address);
      Mpz_Import (Rop    => Bn_Yb,
                  Count  => Yb'Length,
                  Order  => 1,
                  Size   => 1,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Yb'Address);

      --  zz = yb^xa mod p

      Mpz_Powm (Rop    => Bn_Zz,
                Base   => Bn_Yb,
                Exp    => Bn_Xa,
                Modulo => Bn_P);

      Mpz_Export (Result => Zz_Addr,
                  Rop    => System.Null_Address,
                  Countp => 0,
                  Order  => 1,
                  Size   => Bytes'Length,
                  Endian => 1,
                  Nails  => 0,
                  Op     => Bn_Zz);

      Mpz_Clear (Integer => Bn_P);
      Mpz_Clear (Integer => Bn_Xa);
      Mpz_Clear (Integer => Bn_Yb);
      Mpz_Clear (Integer => Bn_Zz);

      declare
         Zz_Bytes : Bytes;
         for Zz_Bytes'Address use Zz_Addr;
      begin
         Zz := Zz_Bytes;
         C_Free (Ptr => Zz_Addr);
      end;
   end Compute_Zz;

end Tkm.Diffie_Hellman;
