with Tkmrpc.Constants;
with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.dh;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.nc;
with Tkmrpc.Contexts.esa;

with Tkm.Logger;
with Tkm.Crypto.Random;
with Tkm.Servers.Ike.Nonce;
with Tkm.Servers.Ike.DH;
with Tkm.Servers.Ike.Ae;
with Tkm.Servers.Ike.Isa;
with Tkm.Servers.Ike.Esa;
with Tkm.Servers.Ike.Cc;

package body Tkmrpc.Servers.Ike
is

   use Tkm;

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   procedure Ae_Reset
     (Result : out Results.Result_Type;
      Ae_Id  : Types.Ae_Id_Type)
   is
   begin
      Tkm.Servers.Ike.Ae.Reset (Ae_Id => Ae_Id);
      Result := Results.Ok;
   end Ae_Reset;

   -------------------------------------------------------------------------

   procedure Cc_Add_Certificate
     (Result      : out Results.Result_Type;
      Cc_Id       : Types.Cc_Id_Type;
      Autha_Id    : Types.Autha_Id_Type;
      Certificate : Types.Certificate_Type)
   is
   begin
      Tkm.Servers.Ike.Cc.Add_Certificate
        (Cc_Id       => Cc_Id,
         Autha_Id    => Autha_Id,
         Certificate => Certificate);
      Result := Results.Ok;
   end Cc_Add_Certificate;

   -------------------------------------------------------------------------

   procedure Cc_Check_Ca
     (Result : out Results.Result_Type;
      Cc_Id  : Types.Cc_Id_Type;
      Ca_Id  : Types.Ca_Id_Type)
   is
   begin
      if Tkm.Servers.Ike.Cc.Check_Ca (Cc_Id => Cc_Id,
                                      Ca_Id => Ca_Id)
      then
         Result := Results.Ok;
      else
         Result := Results.Sign_Failure;
      end if;
   end Cc_Check_Ca;

   -------------------------------------------------------------------------

   procedure Cc_Reset
     (Result : out Results.Result_Type;
      Cc_Id  : Types.Cc_Id_Type)
   is
   begin
      Tkm.Servers.Ike.Cc.Reset (Cc_Id => Cc_Id);
      Result := Results.Ok;
   end Cc_Reset;

   -------------------------------------------------------------------------

   procedure Cc_Set_User_Certificate
     (Result      : out Results.Result_Type;
      Cc_Id       : Types.Cc_Id_Type;
      Ri_Id       : Types.Ri_Id_Type;
      Autha_Id    : Types.Autha_Id_Type;
      Certificate : Types.Certificate_Type)
   is
   begin
      Tkm.Servers.Ike.Cc.Set_User_Certificate
        (Cc_Id       => Cc_Id,
         Ri_Id       => Ri_Id,
         Autha_Id    => Autha_Id,
         Certificate => Certificate);
      Result := Results.Ok;
   end Cc_Set_User_Certificate;

   -------------------------------------------------------------------------

   procedure Dh_Create
     (Result   : out Results.Result_Type;
      Dh_Id    : Types.Dh_Id_Type;
      Dha_Id   : Types.Dha_Id_Type;
      Pubvalue : out Types.Dh_Pubvalue_Type)
   is
   begin
      Pubvalue := Tkm.Servers.Ike.DH.Create
        (Id    => Dh_Id,
         Group => Dha_Id);
      Result := Results.Ok;
   end Dh_Create;

   -------------------------------------------------------------------------

   procedure Dh_Generate_Key
     (Result   : out Results.Result_Type;
      Dh_Id    : Types.Dh_Id_Type;
      Pubvalue : Types.Dh_Pubvalue_Type)
   is
   begin
      Tkm.Servers.Ike.DH.Generate_Key
        (Id       => Dh_Id,
         Pubvalue => Pubvalue);
      Result := Results.Ok;
   end Dh_Generate_Key;

   -------------------------------------------------------------------------

   procedure Dh_Reset
     (Result : out Results.Result_Type;
      Dh_Id  : Types.Dh_Id_Type)
   is
   begin
      Tkm.Servers.Ike.DH.Reset (Id => Dh_Id);
      Result := Results.Ok;
   end Dh_Reset;

   -------------------------------------------------------------------------

   procedure Esa_Create
     (Result      : out Results.Result_Type;
      Esa_Id      : Types.Esa_Id_Type;
      Isa_Id      : Types.Isa_Id_Type;
      Sp_Id       : Types.Sp_Id_Type;
      Ea_Id       : Types.Ea_Id_Type;
      Dh_Id       : Types.Dh_Id_Type;
      Nc_Loc_Id   : Types.Nc_Id_Type;
      Nonce_Rem   : Types.Nonce_Type;
      Initiator   : Types.Init_Type;
      Esp_Spi_Loc : Types.Esp_Spi_Type;
      Esp_Spi_Rem : Types.Esp_Spi_Type)
   is
   begin
      Tkm.Servers.Ike.Esa.Create
        (Esa_Id      => Esa_Id,
         Isa_Id      => Isa_Id,
         Sp_Id       => Sp_Id,
         Ea_Id       => Ea_Id,
         Dh_Id       => Dh_Id,
         Nc_Loc_Id   => Nc_Loc_Id,
         Nonce_Rem   => Nonce_Rem,
         Initiator   => Initiator,
         Esp_Spi_Loc => Esp_Spi_Loc,
         Esp_Spi_Rem => Esp_Spi_Rem);
      Result := Results.Ok;
   end Esa_Create;

   -------------------------------------------------------------------------

   procedure Esa_Create_First
     (Result      : out Results.Result_Type;
      Esa_Id      : Types.Esa_Id_Type;
      Isa_Id      : Types.Isa_Id_Type;
      Sp_Id       : Types.Sp_Id_Type;
      Ea_Id       : Types.Ea_Id_Type;
      Esp_Spi_Loc : Types.Esp_Spi_Type;
      Esp_Spi_Rem : Types.Esp_Spi_Type)
   is
   begin
      Tkm.Servers.Ike.Esa.Create_First
        (Esa_Id      => Esa_Id,
         Isa_Id      => Isa_Id,
         Sp_Id       => Sp_Id,
         Ea_Id       => Ea_Id,
         Esp_Spi_Loc => Esp_Spi_Loc,
         Esp_Spi_Rem => Esp_Spi_Rem);
      Result := Results.Ok;
   end Esa_Create_First;

   -------------------------------------------------------------------------

   procedure Esa_Create_No_Pfs
     (Result      : out Results.Result_Type;
      Esa_Id      : Types.Esa_Id_Type;
      Isa_Id      : Types.Isa_Id_Type;
      Sp_Id       : Types.Sp_Id_Type;
      Ea_Id       : Types.Ea_Id_Type;
      Nc_Loc_Id   : Types.Nc_Id_Type;
      Nonce_Rem   : Types.Nonce_Type;
      Initiator   : Types.Init_Type;
      Esp_Spi_Loc : Types.Esp_Spi_Type;
      Esp_Spi_Rem : Types.Esp_Spi_Type)
   is
   begin
      Tkm.Servers.Ike.Esa.Create_No_Pfs
        (Esa_Id      => Esa_Id,
         Isa_Id      => Isa_Id,
         Sp_Id       => Sp_Id,
         Ea_Id       => Ea_Id,
         Nc_Loc_Id   => Nc_Loc_Id,
         Nonce_Rem   => Nonce_Rem,
         Initiator   => Initiator,
         Esp_Spi_Loc => Esp_Spi_Loc,
         Esp_Spi_Rem => Esp_Spi_Rem);
      Result := Results.Ok;
   end Esa_Create_No_Pfs;

   -------------------------------------------------------------------------

   procedure Esa_Reset
     (Result : out Results.Result_Type;
      Esa_Id : Types.Esa_Id_Type)
   is
   begin
      Tkm.Servers.Ike.Esa.Reset (Esa_Id => Esa_Id);
      Result := Results.Ok;
   end Esa_Reset;

   -------------------------------------------------------------------------

   procedure Esa_Select
     (Result : out Results.Result_Type;
      Esa_Id : Types.Esa_Id_Type)
   is
      pragma Unreferenced (Esa_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Esa_Select;

   -------------------------------------------------------------------------

   procedure Finalize
   is
   begin
      Crypto.Random.Finalize;
   end Finalize;

   -------------------------------------------------------------------------

   procedure Init
   is
   begin
      Crypto.Random.Init;
   end Init;

   -------------------------------------------------------------------------

   procedure Isa_Auth
     (Result       : out Results.Result_Type;
      Isa_Id       : Types.Isa_Id_Type;
      Cc_Id        : Types.Cc_Id_Type;
      Init_Message : Types.Init_Message_Type;
      Signature    : Types.Signature_Type)
   is
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Cc_Id);
      pragma Unreferenced (Init_Message);
      pragma Unreferenced (Signature);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Isa_Auth;

   -------------------------------------------------------------------------

   procedure Isa_Auth_Psk
     (Result    : out Results.Result_Type;
      Isa_Id    : Types.Isa_Id_Type;
      Signature : Types.Signature_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Auth_Psk (Isa_Id    => Isa_Id,
                                    Signature => Signature);
      Result := Results.Ok;
   end Isa_Auth_Psk;

   -------------------------------------------------------------------------

   procedure Isa_Create
     (Result    : out Results.Result_Type;
      Isa_Id    : Types.Isa_Id_Type;
      Ae_Id     : Types.Ae_Id_Type;
      Ia_Id     : Types.Ia_Id_Type;
      Dh_Id     : Types.Dh_Id_Type;
      Nc_Loc_Id : Types.Nc_Id_Type;
      Nonce_Rem : Types.Nonce_Type;
      Initiator : Types.Init_Type;
      Spi_Loc   : Types.Ike_Spi_Type;
      Spi_Rem   : Types.Ike_Spi_Type;
      Sk_Ai     : out Types.Key_Type;
      Sk_Ar     : out Types.Key_Type;
      Sk_Ei     : out Types.Key_Type;
      Sk_Er     : out Types.Key_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Create
        (Isa_Id    => Isa_Id,
         Ae_Id     => Ae_Id,
         Ia_Id     => Ia_Id,
         Dh_Id     => Dh_Id,
         Nc_Loc_Id => Nc_Loc_Id,
         Nonce_Rem => Nonce_Rem,
         Initiator => Initiator,
         Spi_Loc   => Spi_Loc,
         Spi_Rem   => Spi_Rem,
         Sk_Ai     => Sk_Ai,
         Sk_Ar     => Sk_Ar,
         Sk_Ei     => Sk_Ei,
         Sk_Er     => Sk_Er);
      Result := Results.Ok;
   end Isa_Create;

   -------------------------------------------------------------------------

   procedure Isa_Create_Child
     (Result        : out Results.Result_Type;
      Isa_Id        : Types.Isa_Id_Type;
      Parent_Isa_Id : Types.Isa_Id_Type;
      Ia_Id         : Types.Ia_Id_Type;
      Dh_Id         : Types.Dh_Id_Type;
      Nc_Loc_Id     : Types.Nc_Id_Type;
      Nonce_Rem     : Types.Nonce_Type;
      Initiator     : Types.Init_Type;
      Spi_Loc       : Types.Ike_Spi_Type;
      Spi_Rem       : Types.Ike_Spi_Type;
      Sk_Ai         : out Types.Key_Type;
      Sk_Ar         : out Types.Key_Type;
      Sk_Ei         : out Types.Key_Type;
      Sk_Er         : out Types.Key_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Create_Child
        (Isa_Id        => Isa_Id,
         Parent_Isa_Id => Parent_Isa_Id,
         Ia_Id         => Ia_Id,
         Dh_Id         => Dh_Id,
         Nc_Loc_Id     => Nc_Loc_Id,
         Nonce_Rem     => Nonce_Rem,
         Initiator     => Initiator,
         Spi_Loc       => Spi_Loc,
         Spi_Rem       => Spi_Rem,
         Sk_Ai         => Sk_Ai,
         Sk_Ar         => Sk_Ar,
         Sk_Ei         => Sk_Ei,
         Sk_Er         => Sk_Er);
      Result := Results.Ok;
   end Isa_Create_Child;

   -------------------------------------------------------------------------

   procedure Isa_Reset
     (Result : out Results.Result_Type;
      Isa_Id : Types.Isa_Id_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Reset (Isa_Id => Isa_Id);
      Result := Results.Ok;
   end Isa_Reset;

   -------------------------------------------------------------------------

   procedure Isa_Sign
     (Result       : out Results.Result_Type;
      Isa_Id       : Types.Isa_Id_Type;
      Lc_Id        : Types.Lc_Id_Type;
      Init_Message : Types.Init_Message_Type;
      Signature    : out Types.Signature_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Sign (Isa_Id       => Isa_Id,
                                Lc_Id        => Lc_Id,
                                Init_Message => Init_Message,
                                Signature    => Signature);
      Result := Results.Ok;
   end Isa_Sign;

   -------------------------------------------------------------------------

   procedure Isa_Sign_Psk
     (Result       : out Results.Result_Type;
      Isa_Id       : Types.Isa_Id_Type;
      Init_Message : Types.Init_Message_Type;
      Idx          : Types.Idx_Type;
      Verify       : Types.Verify_Type;
      Signature    : out Types.Signature_Type)
   is
   begin
      Tkm.Servers.Ike.Isa.Sign_Psk
        (Isa_Id       => Isa_Id,
         Init_Message => Init_Message,
         Idx          => Idx,
         Verify       => Verify,
         Signature    => Signature);
      Result := Results.Ok;
   end Isa_Sign_Psk;

   -------------------------------------------------------------------------

   procedure Isa_Skip_Create_First
     (Result : out Results.Result_Type;
      Isa_Id : Types.Isa_Id_Type)
   is
      pragma Unreferenced (Isa_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Isa_Skip_Create_First;

   -------------------------------------------------------------------------

   procedure Nc_Create
     (Result       : out Results.Result_Type;
      Nc_Id        : Types.Nc_Id_Type;
      Nonce_Length : Types.Nonce_Length_Type;
      Nonce        : out Types.Nonce_Type)
   is
   begin
      Nonce := Tkm.Servers.Ike.Nonce.Create
        (Id     => Nc_Id,
         Length => Nonce_Length);
      Result := Results.Ok;
   end Nc_Create;

   -------------------------------------------------------------------------

   procedure Nc_Reset
     (Result : out Results.Result_Type;
      Nc_Id  : Types.Nc_Id_Type)
   is
   begin
      Tkm.Servers.Ike.Nonce.Reset (Id => Nc_Id);
      Result := Results.Ok;
   end Nc_Reset;

   -------------------------------------------------------------------------

   procedure Tkm_Limits
     (Result              : out Results.Result_Type;
      Max_Active_Requests : out Types.Active_Requests_Type;
      Nc_Contexts         : out Types.Nc_Id_Type;
      Dh_Contexts         : out Types.Dh_Id_Type;
      Cc_Contexts         : out Types.Cc_Id_Type;
      Ae_Contexts         : out Types.Ae_Id_Type;
      Isa_Contexts        : out Types.Isa_Id_Type;
      Esa_Contexts        : out Types.Esa_Id_Type)
   is
   begin

      --  Processing of requests in parallel is not yet supported.

      Max_Active_Requests := 1;

      Nc_Contexts  := Tkmrpc.Types.Nc_Id_Type'Last;
      Dh_Contexts  := Tkmrpc.Types.Dh_Id_Type'Last;
      Cc_Contexts  := Tkmrpc.Types.Cc_Id_Type'Last;
      Ae_Contexts  := Tkmrpc.Types.Ae_Id_Type'Last;
      Isa_Contexts := Tkmrpc.Types.Isa_Id_Type'Last;
      Esa_Contexts := Tkmrpc.Types.Esa_Id_Type'Last;

      Result := Results.Ok;
   end Tkm_Limits;

   -------------------------------------------------------------------------

   procedure Tkm_Reset (Result : out Results.Result_Type)
   is
   begin
      L.Log (Message => "Resetting all contexts");

      for I in Tkmrpc.Types.Nc_Id_Type'Range loop
         Tkmrpc.Contexts.nc.reset (Id => I);
      end loop;
      for I in Tkmrpc.Types.Dh_Id_Type'Range loop
         Tkmrpc.Contexts.dh.reset (Id => I);
      end loop;
      for I in Tkmrpc.Types.Ae_Id_Type'Range loop
         Tkmrpc.Contexts.ae.reset (Id => I);
      end loop;
      for I in Tkmrpc.Types.Isa_Id_Type'Range loop
         Tkmrpc.Contexts.isa.reset (Id => I);
      end loop;
      for I in Tkmrpc.Types.Esa_Id_Type'Range loop
         Tkmrpc.Contexts.esa.reset (Id => I);
      end loop;

      Result := Results.Ok;
   end Tkm_Reset;

   -------------------------------------------------------------------------

   procedure Tkm_Version
     (Result  : out Results.Result_Type;
      Version : out Types.Version_Type)
   is
   begin
      Version := Tkmrpc.Constants.Ike_Version;
      Result  := Results.Ok;
   end Tkm_Version;

end Tkmrpc.Servers.Ike;
