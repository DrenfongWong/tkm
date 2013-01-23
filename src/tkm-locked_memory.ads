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

generic
   type Element_Type (<>) is private;

package Tkm.Locked_Memory
is

   procedure Lock (Object : not null access Element_Type);
   --  Lock memory allocated by given object. This prevents that the object's
   --  memory region is paged to the swap area by the kernel. A Locking_Error
   --  exception is raised if paging could not be disabled.

   procedure Wipe (Object : not null access Element_Type);
   --  Securely wipe memory region allocated by the given object.

   procedure Unlock (Object : not null access Element_Type);
   --  Unlock memory region allocated by given object. After this call, all
   --  pages that contain a part of the object's memory range can be moved to
   --  external swap space again by the kernel. A Locking_Error exception is
   --  raised if paging could not be enabled.

   Locking_Error : exception;

end Tkm.Locked_Memory;
