with Tkmrpc.Types;

package Tkm.Servers.Ike.Cc
is

   procedure Add_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type);
   --  Add given certificate to certificate chain context specified by id.

   function Check_Ca
     (Cc_Id : Tkmrpc.Types.Cc_Id_Type;
      Ca_Id : Tkmrpc.Types.Ca_Id_Type)
      return Boolean;
   --  Check if specified certificate chain context is based on a trusted CA.

   procedure Set_User_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Ri_Id       : Tkmrpc.Types.Ri_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type);
   --  Set user certificate for specified certificate chain context.

   procedure Reset (Cc_Id : Tkmrpc.Types.Cc_Id_Type);
   --  Reset certificate chain context with given id.

end Tkm.Servers.Ike.Cc;
