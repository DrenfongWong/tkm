with Tkmrpc.Types;

package Tkm.Servers.Ike.Nonce
is

   function Create
     (Id     : Tkmrpc.Types.Nc_Id_Type;
      Length : Tkmrpc.Types.Nonce_Length_Type)
      return Tkmrpc.Types.Nonce_Type;
   --  Create a new nonce with given context id and length.

   procedure Reset (Id : Tkmrpc.Types.Nc_Id_Type);
   --  Reset nonce context with given id.

end Tkm.Servers.Ike.Nonce;
