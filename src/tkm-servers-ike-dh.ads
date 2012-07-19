with Tkmrpc.Types;

package Tkm.Servers.Ike.DH
is

   function Create
     (Id    : Tkmrpc.Types.Dh_Id_Type;
      Group : Tkmrpc.Types.Dha_Id_Type)
      return Tkmrpc.Types.Dh_Pubvalue_Type;
   --  Create a new DH context with given id using parameters of specified DH
   --  group. Returns the calculated pubvalue (ya).

   procedure Generate_Key
     (Id       : Tkmrpc.Types.Dh_Id_Type;
      Pubvalue : Tkmrpc.Types.Dh_Pubvalue_Type);
   --  Calculate shared secret using DH context given by id and 'other'
   --  pubvalue (yb).

   function Get_Shared_Secret
     (Id : Tkmrpc.Types.Dh_Id_Type)
      return Tkmrpc.Types.Dh_Key_Type;
   --  DEBUG : Return shared secret (zz) of given DH context.
   --  TODO  : Remove this function as soon as key derivation is implemented.

   procedure Reset (Id : Tkmrpc.Types.Dh_Id_Type);
   --  Reset DH context with given id.

end Tkm.Servers.Ike.DH;
