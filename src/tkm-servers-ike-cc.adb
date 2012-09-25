with Tkmrpc.Contexts.cc;

with Tkm.Logger;

package body Tkm.Servers.Ike.Cc
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Add_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type)
   is
      pragma Unreferenced (Autha_Id, Certificate);
   begin
      L.Log (Message => "Adding certificate to CC context" & Cc_Id'Img);
   end Add_Certificate;

   -------------------------------------------------------------------------

   function Check_Ca
     (Cc_Id : Tkmrpc.Types.Cc_Id_Type;
      Ca_Id : Tkmrpc.Types.Ca_Id_Type)
      return Boolean
   is
      pragma Unreferenced (Ca_Id);
   begin
      L.Log (Message => "Checking CA certificate of CC context" & Cc_Id'Img);
      return True;
   end Check_Ca;

   -------------------------------------------------------------------------

   procedure Reset (Cc_Id : Tkmrpc.Types.Cc_Id_Type)
   is
   begin
      L.Log (Message => "Resetting CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.reset (Id => Cc_Id);
   end Reset;

   -------------------------------------------------------------------------

   procedure Set_User_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Ri_Id       : Tkmrpc.Types.Ri_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type)
   is
   begin
      L.Log (Message => "Setting user certificate for CC context" & Cc_Id'Img);
      Tkmrpc.Contexts.cc.create
        (Id          => Cc_Id,
         authag_id   => Autha_Id,
         ri_id       => Ri_Id,
         certificate => Certificate,
         not_before  => 1,
         not_after   => 1);
   end Set_User_Certificate;

end Tkm.Servers.Ike.Cc;
