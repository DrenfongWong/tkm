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

package Tkm.Diffie_Hellman
is

   --  Supported DH algorithms.
   Dha_Modp_3072 : constant := 1;
   Dha_Modp_4096 : constant := 2;

   procedure Compute_Xa_Ya
     (Dha_Id       :     Tkmrpc.Types.Dh_Algorithm_Type;
      Random_Bytes :     Tkmrpc.Types.Byte_Sequence;
      Xa           : out Tkmrpc.Types.Byte_Sequence;
      Ya           : out Tkmrpc.Types.Byte_Sequence);
   --  Compute DH xa (secret) and ya (my pubvalue) using given random bytes for
   --  given DH group. Currently, only DH group 'Modp_4096' is supported.

   procedure Compute_Zz
     (Dha_Id :     Tkmrpc.Types.Dh_Algorithm_Type;
      Xa     :     Tkmrpc.Types.Byte_Sequence;
      Yb     :     Tkmrpc.Types.Byte_Sequence;
      Zz     : out Tkmrpc.Types.Byte_Sequence);
   --  Compute DH zz (shared secret) using given xa (secret) and yb (other
   --  pubvalue) for given DH group. Currently, only DH group 'Modp_4096' is
   --  supported.

   function Get_Group_Size
     (Dha_Id : Tkmrpc.Types.Dh_Algorithm_Type)
      return Tkmrpc.Types.Byte_Sequence_Range;
   --  Returns the byte sequence size for the Diffie-Hellman group specified by
   --  group id.

   DH_Error : exception;

end Tkm.Diffie_Hellman;
