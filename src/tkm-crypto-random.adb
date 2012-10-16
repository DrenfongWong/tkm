with Ada.Sequential_IO;

package body Tkm.Crypto.Random
is

   package S_IO is new Ada.Sequential_IO (Element_Type => Tkmrpc.Types.Byte);
   use S_IO;

   Random_File : File_Type;
   Random_Path : constant String := "/dev/urandom";
   --  Path to our random source.

   -------------------------------------------------------------------------

   procedure Finalize
   is
   begin
      if Is_Open (File => Random_File) then
         Close (File => Random_File);
      end if;
   end Finalize;

   -------------------------------------------------------------------------

   function Get
     (Size : Tkmrpc.Types.Byte_Sequence_Range)
      return Tkmrpc.Types.Byte_Sequence
   is
      Bytes : Tkmrpc.Types.Byte_Sequence (1 .. Size);
   begin
      for B in Bytes'Range loop
         Read (File => Random_File,
               Item => Bytes (B));
      end loop;

      return Bytes;
   end Get;

   -------------------------------------------------------------------------

   procedure Init
   is
   begin
      Open (File => Random_File,
            Mode => In_File,
            Name => Random_Path,
            Form => "shared=yes");

   exception
      when others =>
         raise Random_Error with "Unable to init random number generator";
   end Init;

end Tkm.Crypto.Random;
