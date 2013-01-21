package Tkm.Identities
is

   type Local_Identity_Type is record
      Id   : Tkmrpc.Types.Li_Id_Type;
      Name : Tkmrpc.Types.Identity_Type;
   end record;
   --  Identity type connects identity id with a name.

   Null_Local_Identity : constant Local_Identity_Type;

   type Local_Identities_Type is array (Positive range <>)
     of Local_Identity_Type;

   function To_Identity (Str : String) return Tkmrpc.Types.Identity_Type;
   --  Create identity type from given string.

private

   Null_Local_Identity : constant Local_Identity_Type
     := (Id => Tkmrpc.Types.Li_Id_Type'First,
         Name => Tkmrpc.Types.Null_Identity_Type);

end Tkm.Identities;
