with Ada.Exceptions;

package Tkm.Callbacks
is

   procedure Receiver_Error
     (E         :        Ada.Exceptions.Exception_Occurrence;
      Stop_Flag : in out Boolean);
   --  Handle error in socket receiver. This handler just logs the exception
   --  occurrence and instructs the receiver to continue.

end Tkm.Callbacks;
