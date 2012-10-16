with X509.Keys;

package Tkm.Private_Key
is

   procedure Load (Path : String);
   --  Load RSA private key from file given by path.

   function Get return X509.Keys.RSA_Private_Key_Type;
   --  Return previously loaded RSA private key. Raises a Key_Uninitialized
   --  exception if no key has been loaded.

   Key_Uninitialized : exception;

end Tkm.Private_Key;
