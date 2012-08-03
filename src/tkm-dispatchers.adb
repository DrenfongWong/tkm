with Ada.Exceptions;

with Tkmrpc.Dispatchers.Ike;

with Tkm.Logger;

package body Tkm.Dispatchers is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Dispatch_Ike_Request
     (Req :     Tkmrpc.Request.Data_Type;
      Res : out Tkmrpc.Response.Data_Type)
   is
   begin
      Tkmrpc.Dispatchers.Ike.Dispatch (Req => Req,
                                       Res => Res);

   exception
      when E : others =>
         L.Log (Level   => L.Error,
                Message => "IKE processing error: "
                & Ada.Exceptions.Exception_Name (X => E)
                & " - "
                & Ada.Exceptions.Exception_Message (X => E));
         Res                   := Tkmrpc.Response.Null_Data;
         Res.Header.Request_Id := Req.Header.Request_Id;
   end Dispatch_Ike_Request;

end Tkm.Dispatchers;
