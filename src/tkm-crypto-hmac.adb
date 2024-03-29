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

with Tkm.Utils;

package body Tkm.Crypto.Hmac
is

   -------------------------------------------------------------------------

   function Generate
     (Ctx  : in out Context_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence
   is
   begin

      --  H(K XOR opad, H(K XOR ipad, data))

      Update (Ctx   => Ctx.Hasher,
              Input => Utils.To_String (Input => Data));

      declare
         Buffer : constant String := Digest (Ctx => Ctx.Hasher);
         Hash   : Hash_Ctx_Type   := Initial_Ctx;
      begin
         Update (Ctx   => Hash,
                 Input => Utils.To_String (Input => Ctx.Opaded_Key));
         Update (Ctx   => Hash,
                 Input => Utils.To_String
                   (Input => Utils.Hex_To_Bytes
                      (Input => Buffer)));

         --  Reinit for next call

         Ctx.Hasher := Initial_Ctx;
         Update (Ctx   => Ctx.Hasher,
                 Input => Utils.To_String (Input => Ctx.Ipaded_Key));

         return Utils.Hex_To_Bytes (Input => Digest (Ctx => Hash));
      end;
   end Generate;

   -------------------------------------------------------------------------

   procedure Init
     (Ctx : in out Context_Type;
      Key :        Tkmrpc.Types.Byte_Sequence)
   is
      use type Tkmrpc.Types.Byte;

      Buffer : Tkmrpc.Types.Byte_Sequence (Ctx.Ipaded_Key'Range)
        := (others => 0);
   begin
      Ctx.Hasher := Initial_Ctx;

      if Key'Length > Buffer'Length then

         --  Hash key if it is too long

         declare
            H : Hash_Ctx_Type := Initial_Ctx;
         begin
            Update (Ctx   => H,
                    Input => Utils.To_String (Input => Key));
            Buffer (1 .. Hash_Length) := Utils.Hex_To_Bytes
              (Input => Digest (Ctx => H));
         end;
      else

         --  Otherwise copy to pre-padded buffer

         Buffer (1 .. Key'Length) := Key;
      end if;

      for I in Positive range 1 .. Hash_Block_Size loop
         Ctx.Ipaded_Key (I) := Buffer (I) xor 16#36#;
         Ctx.Opaded_Key (I) := Buffer (I) xor 16#5c#;
      end loop;

      Update (Ctx   => Ctx.Hasher,
              Input => Utils.To_String (Input => Ctx.Ipaded_Key));
   end Init;

end Tkm.Crypto.Hmac;
