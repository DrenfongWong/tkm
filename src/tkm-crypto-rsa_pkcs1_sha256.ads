with GNAT.SHA256;

with Tkm.Digests;
with Tkm.Crypto.Rsa_Pkcs1;

pragma Elaborate_All (Tkm.Crypto.Rsa_Pkcs1);

package Tkm.Crypto.Rsa_Pkcs1_Sha256 is
  new Tkm.Crypto.Rsa_Pkcs1
    (Hash_Ctx_Type => GNAT.SHA256.Context,
     Initial_Ctx   => GNAT.SHA256.Initial_Context,
     Digest_Info   => Digests.Sha256_Digest_Info,
     Update        => GNAT.SHA256.Update,
     Digest        => GNAT.SHA256.Digest);
