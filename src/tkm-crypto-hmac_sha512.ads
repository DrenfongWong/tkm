with GNAT.SHA512;

with Tkm.Crypto.Hmac;

pragma Elaborate_All (Tkm.Crypto.Hmac);

package Tkm.Crypto.Hmac_Sha512 is new Tkm.Crypto.Hmac
  (Hash_Block_Size => 128,
   Hash_Length     => 64,
   Hash_Ctx_Type   => GNAT.SHA512.Context,
   Initial_Ctx     => GNAT.SHA512.Initial_Context,
   Update          => GNAT.SHA512.Update,
   Digest          => GNAT.SHA512.Digest);
