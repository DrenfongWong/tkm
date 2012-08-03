with Tkmrpc.Contexts.Dh;

with Tkm.Logger;
with Tkm.Random;
with Tkm.Diffie_Hellman;

package body Tkm.Servers.Ike.DH
is

   package L renames Tkm.Logger;

   -------------------------------------------------------------------------

   function Create
     (Id    : Tkmrpc.Types.Dh_Id_Type;
      Group : Tkmrpc.Types.Dha_Id_Type)
      return Tkmrpc.Types.Dh_Pubvalue_Type
   is
      Group_Size           : constant Tkmrpc.Types.Byte_Sequence_Range
        := Diffie_Hellman.Get_Group_Size (Group_Id => Group);
      Random_Chunk, Xa, Ya : Tkmrpc.Types.Byte_Sequence (1 .. Group_Size);
      Priv                 : Tkmrpc.Types.Dh_Priv_Type
        := Tkmrpc.Types.Null_Dh_Priv_Type;
   begin
      L.Log (Message => "Creating DH context for group" & Group'Img
             & ", context" & Id'Img);

      Random_Chunk := Random.Get (Size => Random_Chunk'Length);

      --  TODO: Once cfg server is implemented do proper mapping of Dha_Id to
      --  DH group Id.

      Diffie_Hellman.Compute_Xa_Ya (Group_Id     => Group,
                                    Random_Bytes => Random_Chunk,
                                    Xa           => Xa,
                                    Ya           => Ya);

      Priv.Size                  := Xa'Length;
      Priv.Data (1 .. Xa'Length) := Xa;
      Tkmrpc.Contexts.Dh.Create (Id       => Id,
                                 Dha_Id   => Group,
                                 Secvalue => Priv);
      L.Log (Message => "DH context" & Id'Img & " created");

      return P : Tkmrpc.Types.Dh_Pubvalue_Type do
         P.Size                  := Ya'Length;
         P.Data (1 .. Ya'Length) := Ya;
      end return;
   end Create;

   -------------------------------------------------------------------------

   procedure Generate_Key
     (Id       : Tkmrpc.Types.Dh_Id_Type;
      Pubvalue : Tkmrpc.Types.Dh_Pubvalue_Type)
   is

      --  TODO: Once cfg server is implemented do proper mapping of Dha_Id to
      --  DH group Id.

      Group_Id   : constant Tkmrpc.Types.Dh_Algorithm_Type
        := Tkmrpc.Contexts.Dh.Get_Dha_Id (Id => Id);
      Group_Size : constant Tkmrpc.Types.Byte_Sequence_Range
        := Diffie_Hellman.Get_Group_Size (Group_Id => Group_Id);
      Priv       : constant Tkmrpc.Types.Dh_Priv_Type
        := Tkmrpc.Contexts.Dh.Get_Secvalue (Id => Id);
      Zz         : Tkmrpc.Types.Byte_Sequence (1 .. Group_Size);
      Key        : Tkmrpc.Types.Dh_Key_Type
        := Tkmrpc.Types.Null_Dh_Key_Type;
   begin
      L.Log (Message => "Generating shared secret for DH context" & Id'Img);
      Diffie_Hellman.Compute_Zz
        (Group_Id => Group_Id,
         Xa       => Priv.Data (1 .. Priv.Size),
         Yb       => Pubvalue.Data (1 .. Pubvalue.Size),
         Zz       => Zz);
      Key.Size                  := Zz'Length;
      Key.Data (1 .. Zz'Length) := Zz;
      Tkmrpc.Contexts.Dh.Generate (Id        => Id,
                                   Dh_Key    => Key,
                                   Timestamp => 0);
   end Generate_Key;

   -------------------------------------------------------------------------

   function Get_Shared_Secret
     (Id : Tkmrpc.Types.Dh_Id_Type)
      return Tkmrpc.Types.Dh_Key_Type
   is
   begin
      L.Log (Message => "Returning shared secret for DH context" & Id'Img);
      return Tkmrpc.Contexts.Dh.Get_Shared_Secret (Id => Id);
   end Get_Shared_Secret;

   -------------------------------------------------------------------------

   procedure Reset (Id : Tkmrpc.Types.Dh_Id_Type)
   is
   begin
      L.Log (Message => "Resetting DH context" & Id'Img);
      Tkmrpc.Contexts.Dh.Reset (Id => Id);
   end Reset;

end Tkm.Servers.Ike.DH;
