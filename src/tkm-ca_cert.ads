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

with X509.Certs;

package Tkm.Ca_Cert
is

   procedure Load (Path : String);
   --  Load CA certificate from file given by path. Raises a Ca_Not_Valid
   --  exception if the validity of the CA certificate could not be verified.

   function Get return X509.Certs.Certificate_Type;
   --  Return previously loaded CA certificate. Raises a Ca_Uninitialized
   --  exception if no CA certificate has been loaded.

   Ca_Uninitialized : exception;
   Ca_Not_Valid     : exception;

end Tkm.Ca_Cert;
