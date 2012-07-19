with Tkmrpc.Types;

package Tkm.Diffie_Hellman
is

   procedure Compute_Xa_Ya
     (Random_Bytes :     Tkmrpc.Types.Byte_Sequence;
      Xa           : out Tkmrpc.Types.Byte_Sequence;
      Ya           : out Tkmrpc.Types.Byte_Sequence);
   --  Compute DH xa (secret) and ya (my pubvalue) using given random bytes.
   --  Currently, only DH group 'Modp_4096' is supported.

   procedure Compute_Zz
     (Xa :     Tkmrpc.Types.Byte_Sequence;
      Yb :     Tkmrpc.Types.Byte_Sequence;
      Zz : out Tkmrpc.Types.Byte_Sequence);
   --  Compute DH zz (shared secret) using given xa (secret) and yb (other
   --  pubvalue). Currently, only DH group 'Modp_4096' is supported.

   DH_Error : exception;

end Tkm.Diffie_Hellman;
