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

with Tkm.Crypto.Random;

package body Random_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Get_Random_Bytes
   is
      subtype Bytes_Type is Tkmrpc.Types.Byte_Sequence (1 .. 4);

      Count      : constant := 1024;
      Previous_R : array (1 .. Count) of Bytes_Type;
      R          : Bytes_Type;

      function Is_Unique
        (Current : Bytes_Type;
         Index   : Positive)
         return Boolean;
      --  Return True if the current bytes are not the same as the previous
      --  bytes.

      function Is_Unique
        (Current : Bytes_Type;
         Index   : Positive)
         return Boolean
      is
         use type Tkmrpc.Types.Byte_Sequence;
      begin
         for P in Integer range 1 .. Index - 1 loop
            if Previous_R (P) = Current then
               return False;
            end if;
         end loop;

         return True;
      end Is_Unique;
   begin
      Crypto.Random.Init;
      for I in 1 .. Count loop
         R := Crypto.Random.Get (Size => Bytes_Type'Length);
         Assert (Condition => Is_Unique
                 (Current => R, Index => I),
                 Message   => "Bytes not random, idx" & I'Img);

         Previous_R (I) := R;
      end loop;

      Crypto.Random.Finalize;

   exception
      when others =>
         Crypto.Random.Finalize;
         raise;
   end Get_Random_Bytes;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Random number generator tests");
      T.Add_Test_Routine
        (Routine => Get_Random_Bytes'Access,
         Name    => "Get random bytes");
   end Initialize;

end Random_Tests;
