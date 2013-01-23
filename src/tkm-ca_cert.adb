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

with X509.Validity;

with Tkm.Logger;

package body Tkm.Ca_Cert
is

   package L renames Tkm.Logger;

   Cacert : X509.Certs.Certificate_Type;

   -------------------------------------------------------------------------

   function Get return X509.Certs.Certificate_Type
   is
      use type X509.Certs.Certificate_Type;
   begin
      if Cacert = X509.Certs.Null_Certificate then
         raise Ca_Uninitialized with "CA certificate not initialized";
      end if;

      return Cacert;
   end Get;

   -------------------------------------------------------------------------

   procedure Load (Path : String)
   is
      use X509;
   begin
      L.Log (Message => "Loading CA certificate '" & Path & "'");
      Certs.Load (Filename => Path,
                  Cert     => Cacert);

      declare
         Subj : constant String := Certs.Get_Subject (Cert => Cacert);
         Val  : constant Validity.Validity_Type
           := Certs.Get_Validity (Cert => Cacert);
      begin
         if not Certs.Is_Ca (Cert => Cacert) then
            raise Ca_Not_Valid with "'" & Subj & "' is not a CA certificate";
         end if;

         if not Validity.Is_Valid (V => Val) then
            raise Ca_Not_Valid with "'" & Subj & "' is not valid";
         end if;
      end;
      L.Log (Message => "CA certificate '" & X509.Certs.Get_Subject
             (Cert => Cacert) & "' loaded");
   end Load;

end Tkm.Ca_Cert;
