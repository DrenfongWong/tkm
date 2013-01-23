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
