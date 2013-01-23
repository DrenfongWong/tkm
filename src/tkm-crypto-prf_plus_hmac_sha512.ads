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

with Tkm.Crypto.Prf_Plus;
with Tkm.Crypto.Hmac_Sha512;

pragma Elaborate_All (Tkm.Crypto.Prf_Plus);

package Tkm.Crypto.Prf_Plus_Hmac_Sha512 is new Tkm.Crypto.Prf_Plus
  (Prf_Length   => Hmac_Sha512.Hash_Output_Length,
   Prf_Ctx_Type => Hmac_Sha512.Context_Type,
   Init         => Hmac_Sha512.Init,
   Generate     => Hmac_Sha512.Generate);
