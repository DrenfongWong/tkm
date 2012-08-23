with Tkm.Crypto.Prf_Plus;
with Tkm.Crypto.Hmac_Sha512;

pragma Elaborate_All (Tkm.Crypto.Prf_Plus);

package Tkm.Crypto.Prf_Plus_Hmac_Sha512 is new Tkm.Crypto.Prf_Plus
  (Prf_Length   => Hmac_Sha512.Hash_Output_Length,
   Prf_Ctx_Type => Hmac_Sha512.Context_Type,
   Init         => Hmac_Sha512.Init,
   Generate     => Hmac_Sha512.Generate);
