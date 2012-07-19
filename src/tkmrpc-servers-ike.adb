with Tkm.Random;
with Tkm.Servers.Ike.Nonce;
with Tkm.Servers.Ike.DH;

pragma Elaborate_All (Tkm.Random);

package body Tkmrpc.Servers.Ike
is

   use Tkm;

   -------------------------------------------------------------------------

   procedure Ae_Reset
     (Result : out Results.Result_Type;
      Ae_Id  : Types.Ae_Id_Type)
   is
      pragma Unreferenced (Ae_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Ae_Reset;

   -------------------------------------------------------------------------

   procedure Cc_Add_Certificate
     (Result      : out Results.Result_Type;
      Cc_Id       : Types.Cc_Id_Type;
      Autha_Id    : Types.Autha_Id_Type;
      Certificate : Types.Certificate_Type)
   is
      pragma Unreferenced (Cc_Id);
      pragma Unreferenced (Autha_Id);
      pragma Unreferenced (Certificate);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Cc_Add_Certificate;

   -------------------------------------------------------------------------

   procedure Cc_Check_Ca
     (Result : out Results.Result_Type;
      Cc_Id  : Types.Cc_Id_Type;
      Ca_Id  : Types.Ca_Id_Type)
   is
      pragma Unreferenced (Cc_Id);
      pragma Unreferenced (Ca_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Cc_Check_Ca;

   -------------------------------------------------------------------------

   procedure Cc_Reset
     (Result : out Results.Result_Type;
      Cc_Id  : Types.Cc_Id_Type)
   is
      pragma Unreferenced (Cc_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Cc_Reset;

   -------------------------------------------------------------------------

   procedure Cc_Set_User_Certificate
     (Result      : out Results.Result_Type;
      Cc_Id       : Types.Cc_Id_Type;
      Ri_Id       : Types.Ri_Id_Type;
      Autha_Id    : Types.Autha_Id_Type;
      Certificate : Types.Certificate_Type)
   is
      pragma Unreferenced (Cc_Id);
      pragma Unreferenced (Ri_Id);
      pragma Unreferenced (Autha_Id);
      pragma Unreferenced (Certificate);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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

   procedure Dh_Get_Shared_Secret
     (Result       : out Results.Result_Type;
      Dh_Id        : Types.Dh_Id_Type;
      Sharedsecret : out Types.Dh_Key_Type)
   is
   begin
      Sharedsecret := Tkm.Servers.Ike.DH.Get_Shared_Secret (Id => Dh_Id);
      Result       := Results.Ok;
   end Dh_Get_Shared_Secret;

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
      pragma Unreferenced (Esa_Id);
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Sp_Id);
      pragma Unreferenced (Ea_Id);
      pragma Unreferenced (Dh_Id);
      pragma Unreferenced (Nc_Loc_Id);
      pragma Unreferenced (Nonce_Rem);
      pragma Unreferenced (Initiator);
      pragma Unreferenced (Esp_Spi_Loc);
      pragma Unreferenced (Esp_Spi_Rem);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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
      pragma Unreferenced (Esa_Id);
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Sp_Id);
      pragma Unreferenced (Ea_Id);
      pragma Unreferenced (Esp_Spi_Loc);
      pragma Unreferenced (Esp_Spi_Rem);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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
      pragma Unreferenced (Esa_Id);
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Sp_Id);
      pragma Unreferenced (Ea_Id);
      pragma Unreferenced (Nc_Loc_Id);
      pragma Unreferenced (Nonce_Rem);
      pragma Unreferenced (Initiator);
      pragma Unreferenced (Esp_Spi_Loc);
      pragma Unreferenced (Esp_Spi_Rem);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Esa_Create_No_Pfs;

   -------------------------------------------------------------------------

   procedure Esa_Reset
     (Result : out Results.Result_Type;
      Esa_Id : Types.Esa_Id_Type)
   is
      pragma Unreferenced (Esa_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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
      Random.Finalize;
   end Finalize;

   -------------------------------------------------------------------------

   procedure Init
   is
   begin
      Random.Init;
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
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Ae_Id);
      pragma Unreferenced (Ia_Id);
      pragma Unreferenced (Dh_Id);
      pragma Unreferenced (Nc_Loc_Id);
      pragma Unreferenced (Nonce_Rem);
      pragma Unreferenced (Initiator);
      pragma Unreferenced (Spi_Loc);
      pragma Unreferenced (Spi_Rem);
      pragma Unreferenced (Sk_Ai);
      pragma Unreferenced (Sk_Ar);
      pragma Unreferenced (Sk_Ei);
      pragma Unreferenced (Sk_Er);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Parent_Isa_Id);
      pragma Unreferenced (Ia_Id);
      pragma Unreferenced (Dh_Id);
      pragma Unreferenced (Nc_Loc_Id);
      pragma Unreferenced (Nonce_Rem);
      pragma Unreferenced (Initiator);
      pragma Unreferenced (Spi_Loc);
      pragma Unreferenced (Spi_Rem);
      pragma Unreferenced (Sk_Ai);
      pragma Unreferenced (Sk_Ar);
      pragma Unreferenced (Sk_Ei);
      pragma Unreferenced (Sk_Er);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Isa_Create_Child;

   -------------------------------------------------------------------------

   procedure Isa_Reset
     (Result : out Results.Result_Type;
      Isa_Id : Types.Isa_Id_Type)
   is
      pragma Unreferenced (Isa_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Isa_Reset;

   -------------------------------------------------------------------------

   procedure Isa_Sign
     (Result       : out Results.Result_Type;
      Isa_Id       : Types.Isa_Id_Type;
      Lc_Id        : Types.Lc_Id_Type;
      Init_Message : Types.Init_Message_Type;
      Signature    : out Types.Signature_Type)
   is
      pragma Unreferenced (Isa_Id);
      pragma Unreferenced (Lc_Id);
      pragma Unreferenced (Init_Message);
      pragma Unreferenced (Signature);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Isa_Sign;

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
      pragma Unreferenced (Nc_Id);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
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
      pragma Unreferenced (Max_Active_Requests);
      pragma Unreferenced (Nc_Contexts);
      pragma Unreferenced (Dh_Contexts);
      pragma Unreferenced (Cc_Contexts);
      pragma Unreferenced (Ae_Contexts);
      pragma Unreferenced (Isa_Contexts);
      pragma Unreferenced (Esa_Contexts);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Tkm_Limits;

   -------------------------------------------------------------------------

   procedure Tkm_Version
     (Result  : out Results.Result_Type;
      Version : out Types.Version_Type)
   is
      pragma Unreferenced (Version);
   begin

      --  Auto-generated stub.

      Result := Results.Invalid_Operation;
   end Tkm_Version;

end Tkmrpc.Servers.Ike;
