with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.dh;
with Tkmrpc.Contexts.nc;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.esa;

with Tkm.Logger;
with Tkm.Utils;
with Tkm.Key_Derivation;
with Tkm.Xfrm;
with Tkm.Locked_Memory;

package body Tkm.Servers.Ike.Esa
is

   package L renames Tkm.Logger;

   type Esp_Spis_Type is record
      Sp_Id  : Tkmrpc.Types.Sp_Id_Type;
      Local  : Tkmrpc.Types.Esp_Spi_Type;
      Remote : Tkmrpc.Types.Esp_Spi_Type;
   end record;

   Esa_Spi_Mapping : array (Tkmrpc.Types.Esa_Id_Type'Range) of Esp_Spis_Type;
   --  Mapping of Esa context id to associated ESP SPIs.
   --  The SPIs are used to delete the corresponding XFRM state when an Esa
   --  context is reset. The SPIs are stored in the array when an Esa context
   --  is created and the associated XFRM states are installed in the kernel.

   procedure Create_Esa
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Dh_Secret   : Tkmrpc.Types.Byte_Sequence;
      Nonce_Loc   : Tkmrpc.Types.Nonce_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Boolean;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create new Esa context with specified parameters.

   use type Tkmrpc.Contexts.ae.ae_State_Type;

   -------------------------------------------------------------------------

   procedure Create
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Dh_Id       : Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id   : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Tkmrpc.Types.Init_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type)
   is
      pragma Precondition (Tkmrpc.Contexts.ae.Get_State
                           (Id => Isa_Id) = Tkmrpc.Contexts.ae.active);
      use type Tkmrpc.Types.Init_Type;

      Secret    : Tkmrpc.Types.Dh_Key_Type;
      Nonce_Loc : Tkmrpc.Types.Nonce_Type;
   begin
      Tkmrpc.Contexts.nc.consume (Id    => Nc_Loc_Id,
                                  nonce => Nonce_Loc);
      Tkmrpc.Contexts.dh.consume (Id     => Dh_Id,
                                  dh_key => Secret);

      L.Log (Message => "Creating ESA context with ID" & Esa_Id'Img
             & " (Isa" & Isa_Id'Img & ", Sp" & Sp_Id'Img
             & ", Ea" & Ea_Id'Img  & ", Dh_Id" & Dh_Id'Img
             & ", Nc_Loc_Id" & Nc_Loc_Id'Img & ", Initiator "
             & Boolean'Image (Initiator = 1)
             & ", spi_loc" & Esp_Spi_Loc'Img & ", spi_rem" & Esp_Spi_Rem'Img
             & ")");
      Create_Esa
        (Esa_Id      => Esa_Id,
         Isa_Id      => Isa_Id,
         Sp_Id       => Sp_Id,
         Ea_Id       => Ea_Id,
         Dh_Secret   => Secret.Data (Secret.Data'First .. Secret.Size),
         Nonce_Loc   => Nonce_Loc,
         Nonce_Rem   => Nonce_Rem,
         Initiator   => Initiator = 1,
         Esp_Spi_Loc => Esp_Spi_Loc,
         Esp_Spi_Rem => Esp_Spi_Rem);
   end Create;

   -------------------------------------------------------------------------

   procedure Create_Esa
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Dh_Secret   : Tkmrpc.Types.Byte_Sequence;
      Nonce_Loc   : Tkmrpc.Types.Nonce_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Boolean;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type)
   is
      package Key_Locker is new Tkm.Locked_Memory
        (Element_Type => Tkmrpc.Types.Key_Type);

      Ae_Id : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
      Sk_D  : constant Tkmrpc.Types.Key_Type
        := Tkmrpc.Contexts.isa.get_sk_d (Id => Isa_Id);

      Enc_I, Enc_R, Int_I, Int_R : aliased Tkmrpc.Types.Key_Type
        := Tkmrpc.Types.Null_Key_Type;
   begin
      Key_Locker.Lock (Object => Enc_I'Access);
      Key_Locker.Lock (Object => Enc_R'Access);
      Key_Locker.Lock (Object => Int_I'Access);
      Key_Locker.Lock (Object => Int_R'Access);

      Key_Derivation.Derive_Child_Keys
        (Sk_D    => Sk_D.Data (Sk_D.Data'First .. Sk_D.Size),
         Secret  => Dh_Secret,
         Nonce_I => (if Initiator then
                     Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size)
                     else
                     Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size)),
         Nonce_R => (if Initiator then
                     Nonce_Rem.Data (Nonce_Rem.Data'First .. Nonce_Rem.Size)
                     else
                     Nonce_Loc.Data (Nonce_Loc.Data'First .. Nonce_Loc.Size)),
         Enc_I   => Enc_I,
         Enc_R   => Enc_R,
         Int_I   => Int_I,
         Int_R   => Int_R);

      L.Log (Message => "Enc_I " & Utils.To_Hex_String
             (Input => Enc_I.Data (Enc_I.Data'First .. Enc_I.Size)));
      L.Log (Message => "Enc_R " & Utils.To_Hex_String
             (Input => Enc_R.Data (Enc_R.Data'First .. Enc_R.Size)));
      L.Log (Message => "Int_I " & Utils.To_Hex_String
             (Input => Int_I.Data (Int_I.Data'First .. Int_I.Size)));
      L.Log (Message => "Int_R " & Utils.To_Hex_String
             (Input => Int_R.Data (Int_R.Data'First .. Int_R.Size)));

      Xfrm.Add_State
        (Policy_Id    => Sp_Id,
         SPI_In       => Esp_Spi_Loc,
         SPI_Out      => Esp_Spi_Rem,
         Enc_Key_In   => (if Initiator then
                           Enc_R.Data (Enc_R.Data'First .. Enc_R.Size)
                           else
                           Enc_I.Data (Enc_I.Data'First .. Enc_I.Size)),
         Enc_Key_Out  => (if Initiator then
                           Enc_I.Data (Enc_I.Data'First .. Enc_I.Size)
                           else
                           Enc_R.Data (Enc_R.Data'First .. Enc_R.Size)),
         Auth_Key_In  => (if Initiator then
                           Int_R.Data (Int_R.Data'First .. Int_R.Size)
                           else
                           Int_I.Data (Int_I.Data'First .. Int_I.Size)),
         Auth_Key_Out => (if Initiator then
                           Int_I.Data (Int_I.Data'First .. Int_I.Size)
                           else
                           Int_R.Data (Int_R.Data'First .. Int_R.Size)));

      Key_Locker.Wipe (Object => Enc_I'Access);
      Key_Locker.Wipe (Object => Enc_R'Access);
      Key_Locker.Wipe (Object => Int_I'Access);
      Key_Locker.Wipe (Object => Int_R'Access);

      Key_Locker.Unlock (Object => Enc_I'Access);
      Key_Locker.Unlock (Object => Enc_R'Access);
      Key_Locker.Unlock (Object => Int_I'Access);
      Key_Locker.Unlock (Object => Int_R'Access);

      Esa_Spi_Mapping (Esa_Id).Sp_Id  := Sp_Id;
      Esa_Spi_Mapping (Esa_Id).Local  := Esp_Spi_Loc;
      Esa_Spi_Mapping (Esa_Id).Remote := Esp_Spi_Rem;

      Tkmrpc.Contexts.esa.create (Id    => Esa_Id,
                                  ae_id => Ae_Id,
                                  ea_id => Ea_Id,
                                  sp_id => Sp_Id);
   end Create_Esa;

   -------------------------------------------------------------------------

   procedure Create_First
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type)
   is
      pragma Precondition (Tkmrpc.Contexts.ae.Get_State
                           (Id => Isa_Id) = Tkmrpc.Contexts.ae.authenticated);

      use type Tkmrpc.Types.Init_Type;

      Ae_Id     : constant Tkmrpc.Types.Ae_Id_Type
        := Tkmrpc.Contexts.isa.get_ae_id (Id => Isa_Id);
      Initiator : constant Boolean := Tkmrpc.Contexts.ae.is_initiator
        (Id => Ae_Id) = 1;
      Nonce_Loc : constant Tkmrpc.Types.Nonce_Type
        := Tkmrpc.Contexts.ae.get_nonce_loc (Id => Ae_Id);
      Nonce_Rem : constant Tkmrpc.Types.Nonce_Type
        := Tkmrpc.Contexts.ae.get_nonce_rem (Id => Ae_Id);
   begin
      L.Log (Message => "Creating first new ESA context with ID" & Esa_Id'Img
             & " (Isa" & Isa_Id'Img & ", Sp" & Sp_Id'Img & ", Ea" & Ea_Id'Img
             & ", Initiator " & Initiator'Img
             & ", spi_loc" & Esp_Spi_Loc'Img & ", spi_rem" & Esp_Spi_Rem'Img
             & ")");
      Create_Esa (Esa_Id      => Esa_Id,
                  Isa_Id      => Isa_Id,
                  Sp_Id       => Sp_Id,
                  Ea_Id       => Ea_Id,
                  Dh_Secret   => Null_Byte_Sequence,
                  Nonce_Loc   => Nonce_Loc,
                  Nonce_Rem   => Nonce_Rem,
                  Initiator   => Initiator,
                  Esp_Spi_Loc => Esp_Spi_Loc,
                  Esp_Spi_Rem => Esp_Spi_Rem);
      Tkmrpc.Contexts.ae.activate (Id => Ae_Id);
   end Create_First;

   -------------------------------------------------------------------------

   procedure Create_No_Pfs
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Nc_Loc_Id   : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Tkmrpc.Types.Init_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type)
   is
      pragma Precondition (Tkmrpc.Contexts.ae.Get_State
                           (Id => Isa_Id) = Tkmrpc.Contexts.ae.active);
      use type Tkmrpc.Types.Init_Type;

      Nonce_Loc : Tkmrpc.Types.Nonce_Type;
   begin
      Tkmrpc.Contexts.nc.consume (Id    => Nc_Loc_Id,
                                  nonce => Nonce_Loc);

      L.Log (Message => "Creating new ESA context (no PFS) with ID"
             & Esa_Id'Img & " (Isa" & Isa_Id'Img & ", Sp" & Sp_Id'Img
             & ", Ea" & Ea_Id'Img  & ", Nc_Loc_Id" & Nc_Loc_Id'Img
             & ", Initiator " & Boolean'Image (Initiator = 1)
             & ", spi_loc" & Esp_Spi_Loc'Img & ", spi_rem" & Esp_Spi_Rem'Img
             & ")");
      Create_Esa (Esa_Id      => Esa_Id,
                  Isa_Id      => Isa_Id,
                  Sp_Id       => Sp_Id,
                  Ea_Id       => Ea_Id,
                  Dh_Secret   => Null_Byte_Sequence,
                  Nonce_Loc   => Nonce_Loc,
                  Nonce_Rem   => Nonce_Rem,
                  Initiator   => Initiator = 1,
                  Esp_Spi_Loc => Esp_Spi_Loc,
                  Esp_Spi_Rem => Esp_Spi_Rem);
   end Create_No_Pfs;

   -------------------------------------------------------------------------

   procedure Reset (Esa_Id : Tkmrpc.Types.Esa_Id_Type)
   is
      use type Tkmrpc.Types.Esp_Spi_Type;
   begin
      L.Log (Message => "Resetting ESA context" & Esa_Id'Img);

      if Esa_Spi_Mapping (Esa_Id).Local /= 0 then
         Xfrm.Delete_State
           (Policy_Id => Esa_Spi_Mapping (Esa_Id).Sp_Id,
            SPI_In    => Esa_Spi_Mapping (Esa_Id).Local,
            SPI_Out   => Esa_Spi_Mapping (Esa_Id).Remote);
         Esa_Spi_Mapping (Esa_Id).Sp_Id  := Tkmrpc.Types.Sp_Id_Type'First;
         Esa_Spi_Mapping (Esa_Id).Local  := 0;
         Esa_Spi_Mapping (Esa_Id).Remote := 0;
      end if;

      Tkmrpc.Contexts.esa.reset (Id => Esa_Id);
   end Reset;

end Tkm.Servers.Ike.Esa;
