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
