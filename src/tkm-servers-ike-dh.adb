with Tkm.Logger;
with Tkm.Random;
with Tkm.Diffie_Hellman;

package body Tkm.Servers.Ike.DH
is

   package L renames Tkm.Logger;

   subtype Bytes is Tkmrpc.Types.Byte_Sequence (1 .. 512);
   --  Byte array needed to store DH MODP_4096 values.

   Xa, Zz : Bytes;
   --  DH secrets.

   Group_Id : Tkmrpc.Types.Dh_Algorithm_Type;

   -------------------------------------------------------------------------

   function Create
     (Id    : Tkmrpc.Types.Dh_Id_Type;
      Group : Tkmrpc.Types.Dha_Id_Type)
      return Tkmrpc.Types.Dh_Pubvalue_Type
   is
      Random_Chunk, Ya : Bytes;
   begin
      L.Log (Message => "Creating DH context for group" & Group'Img
             & ", context" & Id'Img);

      Random_Chunk := Random.Get (Size => Random_Chunk'Length);

      --  TODO: Once cfg server is implemented do proper mapping of Dha_Id to
      --  DH group Id.

      Group_Id := Group;

      Diffie_Hellman.Compute_Xa_Ya (Group_Id     => Group_Id,
                                    Random_Bytes => Random_Chunk,
                                    Xa           => Xa,
                                    Ya           => Ya);

      return P : Tkmrpc.Types.Dh_Pubvalue_Type do
         P.Size := Ya'Length;
         P.Data := Ya;
      end return;
   end Create;

   -------------------------------------------------------------------------

   procedure Generate_Key
     (Id       : Tkmrpc.Types.Dh_Id_Type;
      Pubvalue : Tkmrpc.Types.Dh_Pubvalue_Type)
   is
   begin
      L.Log (Message => "Generating shared secret for DH context" & Id'Img);
      Diffie_Hellman.Compute_Zz (Group_Id => Group_Id,
                                 Xa       => Xa,
                                 Yb       => Pubvalue.Data,
                                 Zz       => Zz);
   end Generate_Key;

   -------------------------------------------------------------------------

   function Get_Shared_Secret
     (Id : Tkmrpc.Types.Dh_Id_Type)
      return Tkmrpc.Types.Dh_Key_Type
   is
   begin
      L.Log (Message => "Returning shared secret for DH context" & Id'Img);
      return K : Tkmrpc.Types.Dh_Key_Type do
         K.Size := Zz'Length;
         K.Data := Zz;
      end return;
   end Get_Shared_Secret;

   -------------------------------------------------------------------------

   procedure Reset (Id : Tkmrpc.Types.Dh_Id_Type)
   is
   begin
      L.Log (Message => "Resetting DH context" & Id'Img);
      Xa := (others => 0);
      Zz := (others => 0);
   end Reset;

end Tkm.Servers.Ike.DH;
