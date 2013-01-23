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

package body Tkm.Crypto.Prf_Plus
is

   -------------------------------------------------------------------------

   function Generate
     (Ctx    : in out Context_Type;
      Length :        Positive)
      return Tkmrpc.Types.Byte_Sequence
   is
      use type Tkmrpc.Types.Byte;

      Result : Tkmrpc.Types.Byte_Sequence (1 .. Length);
      L, M   : Natural;
      --  L : Remaining bytes to generate, M : Bytes per loop to copy
   begin
      L := Length;

      while L > 0 loop
         if L >= Prf_Length
           or else L + Ctx.Consumed >= Prf_Length
         then
            M := Prf_Length;
         else
            M := L + Ctx.Consumed;
         end if;

         declare
            Left_Idx  : constant Positive := Result'First + (Length - L);
            Right_Idx : constant Positive := Left_Idx + M - Ctx.Consumed - 1;
         begin
            Result (Left_Idx .. Right_Idx) := Ctx.Buffer
              (Ctx.Buffer'First + Ctx.Consumed .. M);
         end;

         L := L - (M - Ctx.Consumed);

         if M = Prf_Length then

            --  Ti = prf(K, S | i)

            Ctx.Buffer (Ctx.Ctr_Idx) := Ctx.Buffer (Ctx.Ctr_Idx) + 1;
            Ctx.Buffer (Ctx.Buffer'First .. Prf_Length) := Generate
              (Ctx  => Ctx.Prf_Context,
               Data => Ctx.Buffer (Ctx.Buffer'First .. Ctx.Ctr_Idx));

            Ctx.Consumed := 0;
         else
            Ctx.Consumed := M;
         end if;
      end loop;

      return Result;
   end Generate;

   -------------------------------------------------------------------------

   procedure Init
     (Ctx  : in out Context_Type;
      Key  :        Tkmrpc.Types.Byte_Sequence;
      Seed :        Tkmrpc.Types.Byte_Sequence)
   is
   begin
      if Seed'Length > Buffer_Size - Prf_Length - 1 then
         raise Prf_Plus_Error with "Seed exceeds allowed size of"
           & Positive'Image (Buffer_Size - Prf_Length - 1);
      end if;

      Ctx.Seed_Idx := Ctx.Buffer'First + Prf_Length;
      Ctx.Ctr_Idx  := Ctx.Seed_Idx + Seed'Length;

      Init (Ctx => Ctx.Prf_Context,
            Key => Key);

      --  Buffer = S | 0x01

      Ctx.Buffer (Ctx.Seed_Idx .. Ctx.Ctr_Idx - 1) := Seed;
      Ctx.Buffer (Ctx.Ctr_Idx)                     := 1;

      --  T1  = prf(K, S | 0x01)

      Ctx.Buffer (Ctx.Buffer'First .. Prf_Length) := Generate
        (Ctx  => Ctx.Prf_Context,
         Data => Ctx.Buffer (Ctx.Seed_Idx .. Ctx.Ctr_Idx));
      Ctx.Consumed := 0;
   end Init;

end Tkm.Crypto.Prf_Plus;
