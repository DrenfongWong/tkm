with Tkmrpc.Contexts.nc;

with Tkm.Random;
with Tkm.Logger;

package body Tkm.Servers.Ike.Nonce
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   function Create
     (Id     : Tkmrpc.Types.Nc_Id_Type;
      Length : Tkmrpc.Types.Nonce_Length_Type)
      return Tkmrpc.Types.Nonce_Type
   is
      Nonce : Tkmrpc.Types.Nonce_Type := Tkmrpc.Types.Null_Nonce_Type;
      Size  : constant Tkmrpc.Types.Byte_Sequence_Range
        := Tkmrpc.Types.Byte_Sequence_Range (Length);
   begin
      L.Log (Message => "Nonce of length" & Length'Img
             & " requested, context" & Id'Img);

      Nonce.Size             := Tkmrpc.Types.Nonce_Type_Range (Length);
      Nonce.Data (1 .. Size) := Random.Get (Size => Size);

      Tkmrpc.Contexts.nc.create (Id    => Id,
                                 nonce => Nonce);
      return Nonce;
   end Create;

   -------------------------------------------------------------------------

   procedure Reset (Id : Tkmrpc.Types.Nc_Id_Type)
   is
   begin
      L.Log (Message => "Resetting nonce context" & Id'Img);
      Tkmrpc.Contexts.nc.reset (Id => Id);
   end Reset;

end Tkm.Servers.Ike.Nonce;
