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

with Tkmrpc.Contexts.nc;

with Tkm.Crypto.Random;
with Tkm.Logger;

package body Tkm.Servers.Ike.Nonce
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   function Create
     (Id     : Tkmrpc.Types.Nc_Id_Type;
      Length : Tkmrpc.Types.Nonce_Length_Type)
      return Tkmrpc.Types.Nonce_Type
   is
      Nonce : Tkmrpc.Types.Nonce_Type := Tkmrpc.Types.Null_Nonce_Type;
      Size  : constant Tkmrpc.Types.Byte_Sequence_Range
        := Tkmrpc.Types.Byte_Sequence_Range (Length);
   begin
      L.Log (Message => "Nonce of length" & Length'Img
             & " requested, context" & Id'Img);

      Nonce.Size             := Tkmrpc.Types.Nonce_Type_Range (Length);
      Nonce.Data (1 .. Size) := Crypto.Random.Get (Size => Size);

      Tkmrpc.Contexts.nc.create (Id    => Id,
                                 nonce => Nonce);
      return Nonce;
   end Create;

   -------------------------------------------------------------------------

   procedure Reset (Id : Tkmrpc.Types.Nc_Id_Type)
   is
   begin
      L.Log (Message => "Resetting nonce context" & Id'Img);
      Tkmrpc.Contexts.nc.reset (Id => Id);
   end Reset;

end Tkm.Servers.Ike.Nonce;
