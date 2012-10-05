with Tkm.Logger;

package body Tkm.Callbacks
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Receiver_Error
     (E         :        Ada.Exceptions.Exception_Occurrence;
      Stop_Flag : in out Boolean)
   is
   begin
      L.Log (Level   => L.Error,
             Message => "Exception in receiver");
      L.Log (Level   => L.Error,
             Message => Ada.Exceptions.Exception_Information (X => E));
      Stop_Flag := False;
   end Receiver_Error;

end Tkm.Callbacks;
