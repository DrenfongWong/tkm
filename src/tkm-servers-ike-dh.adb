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

with Tkmrpc.Contexts.dh;

with Tkm.Logger;
with Tkm.Crypto.Random;
with Tkm.Diffie_Hellman;

package body Tkm.Servers.Ike.DH
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   function Create
     (Id     : Tkmrpc.Types.Dh_Id_Type;
      Dha_Id : Tkmrpc.Types.Dha_Id_Type)
      return Tkmrpc.Types.Dh_Pubvalue_Type
   is
      Group_Size       : constant Tkmrpc.Types.Byte_Sequence_Range
        := Diffie_Hellman.Get_Group_Size
          (Dha_Id => Tkmrpc.Types.Dh_Algorithm_Type (Dha_Id));
      Random_Chunk, Ya : Tkmrpc.Types.Byte_Sequence (1 .. Group_Size);
      Priv             : Tkmrpc.Types.Dh_Priv_Type
        := Tkmrpc.Types.Null_Dh_Priv_Type;
   begin
      L.Log (Message => "Creating DH context with algorithm" & Dha_Id'Img
             & ", context" & Id'Img);

      Random_Chunk := Crypto.Random.Get (Size => Random_Chunk'Length);

      Diffie_Hellman.Compute_Xa_Ya
        (Dha_Id       => Tkmrpc.Types.Dh_Algorithm_Type (Dha_Id),
         Random_Bytes => Random_Chunk,
         Xa           => Priv.Data (1 .. Group_Size),
         Ya           => Ya);
      Priv.Size := Group_Size;
      Tkmrpc.Contexts.dh.create (Id       => Id,
                                 dha_id   => Dha_Id,
                                 secvalue => Priv);
      L.Log (Message => "DH context" & Id'Img & " created");

      return P : Tkmrpc.Types.Dh_Pubvalue_Type do
         P.Size                  := Ya'Length;
         P.Data (1 .. Ya'Length) := Ya;
      end return;
   end Create;

   -------------------------------------------------------------------------

   procedure Generate_Key
     (Id       : Tkmrpc.Types.Dh_Id_Type;
      Pubvalue : Tkmrpc.Types.Dh_Pubvalue_Type)
   is
      Dha_Id     : constant Tkmrpc.Types.Dh_Algorithm_Type
        := Tkmrpc.Types.Dh_Algorithm_Type
          (Tkmrpc.Contexts.dh.get_dha_id (Id => Id));
      Group_Size : constant Tkmrpc.Types.Byte_Sequence_Range
        := Diffie_Hellman.Get_Group_Size (Dha_Id => Dha_Id);
      Priv       : constant Tkmrpc.Types.Dh_Priv_Type
        := Tkmrpc.Contexts.dh.get_secvalue (Id => Id);
      Key        : Tkmrpc.Types.Dh_Key_Type
        := Tkmrpc.Types.Null_Dh_Key_Type;
   begin
      L.Log (Message => "Generating shared secret for DH context" & Id'Img);
      Diffie_Hellman.Compute_Zz
        (Dha_Id => Dha_Id,
         Xa     => Priv.Data (1 .. Priv.Size),
         Yb     => Pubvalue.Data (1 .. Pubvalue.Size),
         Zz     => Key.Data (1 .. Group_Size));
      Key.Size := Group_Size;
      Tkmrpc.Contexts.dh.generate (Id        => Id,
                                   dh_key    => Key,
                                   timestamp => 0);
   end Generate_Key;

   -------------------------------------------------------------------------

   procedure Reset (Id : Tkmrpc.Types.Dh_Id_Type)
   is
   begin
      L.Log (Message => "Resetting DH context" & Id'Img);
      Tkmrpc.Contexts.dh.reset (Id => Id);
   end Reset;

end Tkm.Servers.Ike.DH;
