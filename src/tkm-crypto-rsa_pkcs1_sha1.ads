with GNAT.SHA1;

with Tkm.Crypto.Rsa_Pkcs1;

pragma Elaborate_All (Tkm.Crypto.Rsa_Pkcs1);

package Tkm.Crypto.Rsa_Pkcs1_Sha1 is
  new Tkm.Crypto.Rsa_Pkcs1
    (Hash_Ctx_Type => GNAT.SHA1.Context,
     Initial_Ctx   => GNAT.SHA1.Initial_Context,
     Update        => GNAT.SHA1.Update,
     Digest        => GNAT.SHA1.Digest);
