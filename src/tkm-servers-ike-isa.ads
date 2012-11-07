with Tkmrpc.Types;

package Tkm.Servers.Ike.Isa
is

   procedure Create
     (Isa_Id    :     Tkmrpc.Types.Isa_Id_Type;
      Ae_Id     :     Tkmrpc.Types.Ae_Id_Type;
      Ia_Id     :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id     :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem :     Tkmrpc.Types.Nonce_Type;
      Initiator :     Tkmrpc.Types.Init_Type;
      Spi_Loc   :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem   :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai     : out Tkmrpc.Types.Key_Type;
      Sk_Ar     : out Tkmrpc.Types.Key_Type;
      Sk_Ei     : out Tkmrpc.Types.Key_Type;
      Sk_Er     : out Tkmrpc.Types.Key_Type);
   --  Create a new ISA context with given id and parameters. Return the
   --  computed authentication and encryption keys.

   procedure Create_Child
     (Isa_Id        :     Tkmrpc.Types.Isa_Id_Type;
      Parent_Isa_Id :     Tkmrpc.Types.Isa_Id_Type;
      Ia_Id         :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id         :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id     :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem     :     Tkmrpc.Types.Nonce_Type;
      Initiator     :     Tkmrpc.Types.Init_Type;
      Spi_Loc       :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem       :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai         : out Tkmrpc.Types.Key_Type;
      Sk_Ar         : out Tkmrpc.Types.Key_Type;
      Sk_Ei         : out Tkmrpc.Types.Key_Type;
      Sk_Er         : out Tkmrpc.Types.Key_Type);
   --  Rekey a ISA by creating a new ISA context with given id and parameters.
   --  Return the computed authentication and encryption keys.

   procedure Sign
     (Isa_Id       :     Tkmrpc.Types.Isa_Id_Type;
      Lc_Id        :     Tkmrpc.Types.Lc_Id_Type;
      Init_Message :     Tkmrpc.Types.Init_Message_Type;
      Signature    : out Tkmrpc.Types.Signature_Type);
   --  Create signature of local authentication octets using given message.

   procedure Sign_Psk
     (Isa_Id       :     Tkmrpc.Types.Isa_Id_Type;
      Init_Message :     Tkmrpc.Types.Init_Message_Type;
      Idx          :     Tkmrpc.Types.Idx_Type;
      Verify       :     Tkmrpc.Types.Verify_Type;
      Signature    : out Tkmrpc.Types.Signature_Type);
   --  Create PSK signature of local authentication octets using given message
   --  and identification payload.

   procedure Auth_Psk
     (Isa_Id    : Tkmrpc.Types.Isa_Id_Type;
      Signature : Tkmrpc.Types.Signature_Type);
   --  Authenticate ISA context identified by id.

   procedure Auth
     (Isa_Id       : Tkmrpc.Types.Isa_Id_Type;
      Cc_Id        : Tkmrpc.Types.Cc_Id_Type;
      Init_Message : Tkmrpc.Types.Init_Message_Type;
      Signature    : Tkmrpc.Types.Signature_Type);
   --  Authenticate ISA context identified by id with specified cc context, IKE
   --  init message and given signature.

   procedure Reset (Isa_Id : Tkmrpc.Types.Isa_Id_Type);
   --  Reset ISA context with given id.

   Authentication_Failure : exception;

end Tkm.Servers.Ike.Isa;
