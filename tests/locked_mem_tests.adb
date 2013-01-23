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

with Tkmrpc.Types;

with Tkm.Locked_Memory;

package body Locked_Mem_Tests
is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Locked memory tests");
      T.Add_Test_Routine
        (Routine => Lock_And_Wipe'Access,
         Name    => "Lock and wipe memory");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Lock_And_Wipe
   is
      use type Tkmrpc.Types.Byte;
      use type Tkmrpc.Types.Byte_Sequence;

      subtype Bytes is Tkmrpc.Types.Byte_Sequence (1 .. 256);

      type My_Record is tagged record
         Size : Integer;
         Data : Bytes;
      end record;

      package Locked_Bytes is new Locked_Memory (Element_Type => Bytes);
      package Locked_Byte is new Locked_Memory
        (Element_Type => Tkmrpc.Types.Byte);
      package Locked_Record is new Locked_Memory
        (Element_Type => My_Record);

      Buffer : aliased Bytes              := (others => 3);
      Ref1   : constant Bytes             := (others => 0);
      B      : aliased Tkmrpc.Types.Byte  := 255;
      Ref2   : constant Tkmrpc.Types.Byte := 0;
      R      : aliased My_Record
        := (Size => 256, Data => (others => 128));
      Ref3   : constant My_Record
        := (Size => 0, Data => (others => 0));
   begin
      Locked_Bytes.Lock (Object => Buffer'Access);
      Locked_Bytes.Wipe (Object => Buffer'Access);
      Locked_Bytes.Unlock (Object => Buffer'Access);
      Assert (Condition => Buffer = Ref1,
              Message   => "Buffer not wiped");

      Locked_Byte.Lock (Object => B'Access);
      Locked_Byte.Wipe (Object => B'Access);
      Locked_Byte.Unlock (Object => B'Access);
      Assert (Condition => B = Ref2,
              Message   => "Byte not wiped");

      Locked_Record.Lock (Object => R'Access);
      Locked_Record.Wipe (Object => R'Access);
      Locked_Record.Unlock (Object => R'Access);
      Assert (Condition => R = Ref3,
              Message   => "Record not wiped");
   end Lock_And_Wipe;

end Locked_Mem_Tests;
