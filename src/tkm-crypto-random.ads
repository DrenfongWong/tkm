with Tkmrpc.Types;

package Tkm.Crypto.Random
is

   procedure Init;
   --  Initialize random number generator.

   function Get
     (Size : Tkmrpc.Types.Byte_Sequence_Range)
      return Tkmrpc.Types.Byte_Sequence;
   --  Request given number of bytes from the random source.

   procedure Finalize;
   --  Finalize random number generator.

   Random_Error : exception;

end Tkm.Crypto.Random;
