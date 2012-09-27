with System.Address_Image;

with Interfaces.C;

with Anet;

with Tkm.Logger;

package body Tkm.Locked_Memory
is

   use type Interfaces.C.size_t;
   use type Interfaces.C.int;

   function C_Mlock
     (Addr : System.Address;
      Len  : Interfaces.C.size_t)
      return Interfaces.C.int;
   pragma Import (C, C_Mlock, "mlock");

   function C_Munlock
     (Addr : System.Address;
      Len  : Interfaces.C.size_t)
      return Interfaces.C.int;
   pragma Import (C, C_Munlock, "munlock");

   procedure C_Memset
     (S : System.Address;
      C : Interfaces.C.int;
      N : Interfaces.C.size_t);
   pragma Import (C, C_Memset, "memset");

   -------------------------------------------------------------------------

   procedure Lock (Object : not null access Element_Type)
   is
      Res     : Interfaces.C.int;
      Size    : constant Interfaces.C.size_t := Object.all'Size / 8;
      Address : constant System.Address      := Object.all'Address;
   begin
      Res := C_Mlock (Addr => Address,
                      Len  => Size);
      Logger.Log (Level   => Logger.Debug,
                  Message => "Locked" & Size'Img & " byte(s) at address "
                  & System.Address_Image (A => Address));

      if Res /= 0 then
         raise Locking_Error with "Unable to lock" & Size'Img & " byte(s) "
           & "at address " & System.Address_Image (A => Address)
           & ": " & Anet.Get_Errno_String;
      end if;
   end Lock;

   -------------------------------------------------------------------------

   procedure Unlock (Object : not null access Element_Type)
   is
      Res     : Interfaces.C.int;
      Size    : constant Interfaces.C.size_t := Object.all'Size / 8;
      Address : constant System.Address      := Object.all'Address;
   begin
      Res := C_Munlock (Addr => Address,
                        Len  => Size);
      Logger.Log (Level   => Logger.Debug,
                  Message => "Unlocked" & Size'Img & " byte(s) at address "
                  & System.Address_Image (A => Address));

      if Res /= 0 then
         raise Locking_Error with "Unable to unlock" & Size'Img & " byte(s) "
           & "at address " & System.Address_Image (A => Address)
           & ": " & Anet.Get_Errno_String;
      end if;
   end Unlock;

   -------------------------------------------------------------------------

   procedure Wipe (Object : not null access Element_Type)
   is
      Size    : constant Interfaces.C.size_t := Object.all'Size / 8;
      Address : constant System.Address      := Object.all'Address;
   begin
      --  !! Wipe memory region !!

      --  This is done using memset(3) and the method described by David
      --  A. Wheeler in the "Secure Programming for Linux and Unix HOWTO",
      --  Section 10.5.
      --
      --  The Inspection_Point pragma ensures that the clear operation on
      --  the memory region is not optimized away by the compiler.
      --
      --  http://dwheeler.com/secure-programs/Secure-Programs-HOWTO/ada.html

      C_Memset (S => Address,
                C => 0,
                N => Size);
      pragma Inspection_Point (Object);
      Logger.Log (Level   => Logger.Debug,
                  Message => "Wiped" & Size'Img & " byte(s) at address "
                  & System.Address_Image (A => Address));
   end Wipe;

end Tkm.Locked_Memory;
