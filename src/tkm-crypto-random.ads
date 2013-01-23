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

package Tkm.Crypto.Random
is

   procedure Init;
   --  Initialize random number generator.

   function Get
     (Size : Tkmrpc.Types.Byte_Sequence_Range)
      return Tkmrpc.Types.Byte_Sequence;
   --  Request given number of bytes from the random source.

   procedure Finalize;
   --  Finalize random number generator.

   Random_Error : exception;

end Tkm.Crypto.Random;
