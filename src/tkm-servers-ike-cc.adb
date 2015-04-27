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

with Ada.Strings.Fixed;

with X509.Certs;
with X509.Keys;
with X509.Validity;

with Tkmrpc.Contexts.cc;

with Tkm.Utils;
with Tkm.Logger;
with Tkm.Ca_Cert;
with Tkm.Config;
with Tkm.Identities;
with Tkm.Crypto.Rsa_Pkcs1_Sha256;

package body Tkm.Servers.Ike.Cc
is

   package L renames Tkm.Logger;

   procedure Validate (Cert : X509.Certs.Certificate_Type);
   --  Check validity of given certificate and raise exception if the check
   --  fails.

   procedure Verify_Identity
     (Cert  : X509.Certs.Certificate_Type;
      Ri_Id : Tkmrpc.Types.Ri_Id_Type);
   --  Check that the subject of the certificate matches the remote identity
   --  specified by id and raise an exception if the identity does not match.

   -------------------------------------------------------------------------

   procedure Add_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type)
   is
      pragma Unreferenced (Autha_Id);

      Raw_Cert     : constant Tkmrpc.Types.Certificate_Type
        := Tkmrpc.Contexts.cc.get_last_cert (Id => Cc_Id);
      Current_Cert : X509.Certs.Certificate_Type;
      Next_Cert    : X509.Certs.Certificate_Type;
   begin
      X509.Certs.Load
        (Buffer => Utils.To_X509_Bytes
           (Item => Raw_Cert.Data (Raw_Cert.Data'First .. Raw_Cert.Size)),
         Cert   => Current_Cert);
      X509.Certs.Load
        (Buffer => Utils.To_X509_Bytes
           (Item => Certificate.Data
              (Certificate.Data'First .. Certificate.Size)),
         Cert   => Next_Cert);

      L.Log (Message => "Verifying signature of '" & X509.Certs.Get_Subject
             (Cert => Current_Cert) & "' with certificate '"
             & X509.Certs.Get_Subject (Cert => Next_Cert) & "'");

      Validate (Cert => Next_Cert);
      if not X509.Certs.Is_Ca (Cert => Next_Cert) then
         raise Invalid_Certificate with "'" & X509.Certs.Get_Subject
           (Cert => Next_Cert) & "' is not a CA certificate";
      end if;

      declare
         package RSA renames Crypto.Rsa_Pkcs1_Sha256;

         Pubkey   : constant X509.Keys.RSA_Public_Key_Type
           := X509.Certs.Get_Public_Key (Cert => Next_Cert);
         Verifier : RSA.Verifier_Type;
      begin
         RSA.Init (Ctx => Verifier,
                   N   => Pubkey.Get_Modulus,
                   E   => Pubkey.Get_Pub_Exponent);

         if not RSA.Verify
           (Ctx       => Verifier,
            Data      => Utils.To_Sequence
              (X509.Certs.Get_Tbs_Data (Current_Cert)),
            Signature => Utils.To_Sequence
              (X509.Certs.Get_Signature (Current_Cert)))
         then
            raise Invalid_Certificate with "Signature of '"
              & X509.Certs.Get_Subject (Cert => Current_Cert) & "' not valid";
         end if;
      end;

      L.Log (Message => "Adding certificate '" & X509.Certs.Get_Subject
             (Cert => Next_Cert) & "' to CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.add_certificate
        (Id          => Cc_Id,
         certificate => Certificate,
         not_before  => 1,
         not_after   => 1);
   end Add_Certificate;

   -------------------------------------------------------------------------

   procedure Check_Ca
     (Cc_Id : Tkmrpc.Types.Cc_Id_Type;
      Ca_Id : Tkmrpc.Types.Ca_Id_Type)
   is
      use type X509.Certs.Certificate_Type;

      Raw_Cert     : constant Tkmrpc.Types.Certificate_Type
        := Tkmrpc.Contexts.cc.get_last_cert (Id => Cc_Id);
      Current_Cert : X509.Certs.Certificate_Type;
   begin
      X509.Certs.Load
        (Buffer => Utils.To_X509_Bytes
           (Item => Raw_Cert.Data (Raw_Cert.Data'First .. Raw_Cert.Size)),
         Cert   => Current_Cert);

      if Tkm.Ca_Cert.Get /= Current_Cert then
         raise Invalid_Certificate with "Untrusted root CA '"
           & X509.Certs.Get_Subject (Cert => Current_Cert) & "'";
      end if;

      L.Log (Message => "Checked CA certificate of CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.check (Id    => Cc_Id,
                                ca_id => Ca_Id);
   end Check_Ca;

   -------------------------------------------------------------------------

   procedure Reset (Cc_Id : Tkmrpc.Types.Cc_Id_Type)
   is
   begin
      L.Log (Message => "Resetting CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.reset (Id => Cc_Id);
   end Reset;

   -------------------------------------------------------------------------

   procedure Set_User_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Ri_Id       : Tkmrpc.Types.Ri_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type)
   is
      User_Cert : X509.Certs.Certificate_Type;
   begin
      X509.Certs.Load
        (Buffer => Utils.To_X509_Bytes
           (Item => Certificate.Data
              (Certificate.Data'First .. Certificate.Size)),
         Cert   => User_Cert);
      Validate (Cert => User_Cert);

      Verify_Identity
        (Cert  => User_Cert,
         Ri_Id => Ri_Id);

      L.Log (Message => "Setting user certificate '"
             & X509.Certs.Get_Subject (Cert => User_Cert)
             & "' for CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.create
        (Id          => Cc_Id,
         authag_id   => Tkmrpc.Types.Authag_Id_Type (Autha_Id),
         ri_id       => Ri_Id,
         certificate => Certificate,
         last_cert   => Certificate,
         not_before  => 1,
         not_after   => 1);
   end Set_User_Certificate;

   -------------------------------------------------------------------------

   procedure Validate (Cert : X509.Certs.Certificate_Type)
   is
      Subject : constant String := X509.Certs.Get_Subject (Cert => Cert);
   begin
      if not X509.Validity.Is_Valid
        (V => X509.Certs.Get_Validity (Cert => Cert))
      then
         raise Invalid_Certificate with "Certificate '" & Subject
           & "' not valid";
      end if;
   end Validate;

   -------------------------------------------------------------------------

   procedure Verify_Identity
     (Cert  : X509.Certs.Certificate_Type;
      Ri_Id : Tkmrpc.Types.Ri_Id_Type)
   is
      Subject    : constant String := X509.Certs.Get_Subject (Cert => Cert);
      R_Identity : constant String := Identities.To_String
        (Identity => Config.Get_Policy
           (Id => Tkmrpc.Types.Sp_Id_Type (Ri_Id)).Remote_Identity);
   begin

      --  Check that identity string is part of subject.

      if Ada.Strings.Fixed.Index (Source  => Subject,
                                   Pattern => R_Identity) = 0
      then
         raise Invalid_Certificate with "Certificate subject '" & Subject
           & "' and remote identity '" & R_Identity & "' mismatch";
      end if;
   end Verify_Identity;

end Tkm.Servers.Ike.Cc;
