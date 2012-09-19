with Tkmrpc.Contexts.ae;

with Tkm.Logger;

package body Tkm.Servers.Ike.Ae
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Reset (Ae_Id : Tkmrpc.Types.Ae_Id_Type)
   is
   begin
      L.Log (Message => "Resetting AE context" & Ae_Id'Img);
      Tkmrpc.Contexts.ae.reset (Id => Ae_Id);
   end Reset;

end Tkm.Servers.Ike.Ae;
