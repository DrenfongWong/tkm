with Tkmrpc.Request;
with Tkmrpc.Response;

package Tkm.Dispatchers is

   procedure Dispatch_Ike_Request
     (Req :     Tkmrpc.Request.Data_Type;
      Res : out Tkmrpc.Response.Data_Type);
   --  Add additional processing (e.g. logging) before calling generated IKE
   --  dispatcher.

end Tkm.Dispatchers;
