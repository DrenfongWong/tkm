with X509.Certs;

with Tkm.Ca_Cert;

package body Cacert_Tests is

   use Ahven;
   use Tkm;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "CA certificate tests");
      T.Add_Test_Routine
        (Routine => Load_Certs'Access,
         Name    => "Load certificates");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Load_Certs
   is
      use type X509.Certs.Certificate_Type;

      Cert : X509.Certs.Certificate_Type;
   begin
      begin
         Cert := Ca_Cert.Get;

      exception
         when Ca_Cert.Ca_Uninitialized => null;
      end;

      begin
         Ca_Cert.Load (Path => "data/cert.der");

      exception
         when Ca_Cert.Ca_Not_Valid => null;
      end;

      begin
         Ca_Cert.Load (Path => "data/ca_invalid.der");

      exception
         when Ca_Cert.Ca_Not_Valid => null;
      end;

      Ca_Cert.Load (Path => "data/ca.der");
      Cert := Ca_Cert.Get;
      Assert (Condition => Cert /= X509.Certs.Null_Certificate,
              Message   => "CA null after load");
   end Load_Certs;

end Cacert_Tests;
