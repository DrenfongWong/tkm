with Tkm.Logger;

package body Tkm.Private_Key
is

   package L renames Tkm.Logger;

   Key : X509.Keys.RSA_Private_Key_Type;

   -------------------------------------------------------------------------

   function Get return X509.Keys.RSA_Private_Key_Type
   is
      use type X509.Keys.RSA_Private_Key_Type;
   begin
      if Key = X509.Keys.Null_Private_Key then
         raise Key_Uninitialized with "Private key not initialized";
      end if;

      return Key;
   end Get;

   -------------------------------------------------------------------------

   procedure Load (Path : String)
   is
   begin
      L.Log (Message => "Loading RSA private key '" & Path & "'");
      X509.Keys.Load (Filename => Path,
                      Key      => Key);
      L.Log (Message => "RSA private key '" & Path & "' loaded, key size"
             & X509.Keys.Get_Size (Key => Key)'Img & " bits");
   end Load;

end Tkm.Private_Key;
