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
with X509.Keys;

with Tkmrpc.Types;

with Tkm.Ca_Cert;
with Tkm.Crypto.Rsa_Pkcs1_Sha256;

package body Cacert_Tests is

   use Ahven;
   use Tkm;

   package RSA renames Tkm.Crypto.Rsa_Pkcs1_Sha256;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "CA certificate tests");
      T.Add_Test_Routine
        (Routine => Load_Certs'Access,
         Name    => "Load certificates");
      T.Add_Test_Routine
        (Routine => Verify_Signature'Access,
         Name    => "Verify certificate signature");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Load_Certs
   is
      use type X509.Certs.Certificate_Type;

      Cert : X509.Certs.Certificate_Type;
   begin
      begin
         Cert := Ca_Cert.Get;
         Fail (Message => "Exception expected");

      exception
         when Ca_Cert.Ca_Uninitialized => null;
      end;

      begin
         Ca_Cert.Load (Path => "data/cert.der");
         Fail (Message => "Exception expected");

      exception
         when Ca_Cert.Ca_Not_Valid => null;
      end;

      begin
         Ca_Cert.Load (Path => "data/ca_invalid.der");
         Fail (Message => "Exception expected");

      exception
         when Ca_Cert.Ca_Not_Valid => null;
      end;

      Ca_Cert.Load (Path => "data/ca.der");
      Cert := Ca_Cert.Get;
      Assert (Condition => Cert /= X509.Certs.Null_Certificate,
              Message   => "CA null after load");
   end Load_Certs;

   -------------------------------------------------------------------------

   procedure Verify_Signature
   is
      use X509;

      function To_Sequence
        (Item : Byte_Array)
         return Tkmrpc.Types.Byte_Sequence;
      --  Convert given X509 byte array to byte sequence.

      function To_Sequence
        (Item : Byte_Array)
         return Tkmrpc.Types.Byte_Sequence
      is
         Result : Tkmrpc.Types.Byte_Sequence (Item'Range);
      begin
         for I in Result'Range loop
            Result (I) := Tkmrpc.Types.Byte (Item (I));
         end loop;

         return Result;
      end To_Sequence;

      Cacert, Usercert : Certs.Certificate_Type;
      Pubkey           : Keys.RSA_Public_Key_Type;
      Verifier         : RSA.Verifier_Type;
   begin
      Certs.Load (Filename => "data/cert.der",
                  Cert     => Usercert);
      Certs.Load (Filename => "data/ca.der",
                  Cert     => Cacert);

      Pubkey := Certs.Get_Public_Key (Cacert);
      RSA.Init (Ctx => Verifier,
                N   => Pubkey.Get_Modulus,
                E   => Pubkey.Get_Pub_Exponent);

      Assert (Condition => RSA.Verify
              (Ctx       => Verifier,
               Data      => To_Sequence (Certs.Get_Tbs_Data (Usercert)),
               Signature => To_Sequence (Certs.Get_Signature (Usercert))),
              Message   => "Signature invalid");
   end Verify_Signature;

end Cacert_Tests;
