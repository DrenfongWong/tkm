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

generic

   Hash_Block_Size : Positive;
   --  Block size used by the associated hasher.

   Hash_Length : Positive;
   --  Hash output length of associated hasher.

   type Hash_Ctx_Type is private;
   --  Associated hasher context.

   Initial_Ctx : Hash_Ctx_Type;

   with procedure Update
     (Ctx   : in out Hash_Ctx_Type;
      Input :        String);
   --  Hasher update procedure.

   with function Digest (Ctx : Hash_Ctx_Type) return String;
   --  Hasher digest function.

package Tkm.Crypto.Hmac
is

   type Context_Type is private;
   --  HMAC context.

   Hash_Output_Length : constant Positive;
   --  Hash output length.

   procedure Init
     (Ctx : in out Context_Type;
      Key :        Tkmrpc.Types.Byte_Sequence);
   --  Initialize HMAC context with given key.

   function Generate
     (Ctx  : in out Context_Type;
      Data :        Tkmrpc.Types.Byte_Sequence)
      return Tkmrpc.Types.Byte_Sequence;
   --  Generate MAC for given data bytes.

private

   Hash_Output_Length : constant Positive := Hash_Length;

   type Context_Type is record
      Hasher     : Hash_Ctx_Type := Initial_Ctx;
      Ipaded_Key : Tkmrpc.Types.Byte_Sequence (1 .. Hash_Block_Size);
      Opaded_Key : Tkmrpc.Types.Byte_Sequence (1 .. Hash_Block_Size);
   end record;

end Tkm.Crypto.Hmac;
