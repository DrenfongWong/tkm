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

with System.Assertions;

with Tkm.Logger;
with Tkm.Crypto.Rsa_Pkcs1_Sha1;
with Tkm.Crypto.Rsa_Pkcs1_Sha256;

package body Tkm.Exceptions
is

   -------------------------------------------------------------------------

   procedure Handle_Exception
     (Ex     :        Ada.Exceptions.Exception_Occurrence;
      Result : in out Tkmrpc.Results.Result_Type)
   is
      use type Ada.Exceptions.Exception_Id;

      Id : constant Ada.Exceptions.Exception_Id
        := Ada.Exceptions.Exception_Identity (X => Ex);
   begin
      Tkm.Logger.Log (Ex => Ex);

      if Id = System.Assertions.Assert_Failure'Identity then

         --  A precondition was not met.

         Result := Tkmrpc.Results.Invalid_State;
      elsif Id = Crypto.Rsa_Pkcs1_Sha1.Signer_Error'Identity
        or Id = Crypto.Rsa_Pkcs1_Sha256.Signer_Error'Identity
      then
         Result := Tkmrpc.Results.Sign_Failure;
      else

         --  All other exceptions are interpreted as abortion of request
         --  processing.

         Result := Tkmrpc.Results.Aborted;
      end if;
   end Handle_Exception;

end Tkm.Exceptions;
