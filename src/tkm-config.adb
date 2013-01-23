--
--  Copyright (C) 2013  Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2013  Adrian-Ken Rueegsegger <ken@codelabs.ch>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

with Ada.Exceptions;
with Ada.Text_IO.Text_Streams;

package body Tkm.Config
is

   -------------------------------------------------------------------------

   procedure Clear
   is
   begin
      Current_Config.Policies     := (others => Null_Security_Policy);
      Policy_Count                := 0;
      Current_Config.L_Identities
        := (others => Identities.Null_Local_Identity);
      L_Ident_Count               := 0;
   end Clear;

   -------------------------------------------------------------------------

   function Get_Local_Identity
     (Id : Tkmrpc.Types.Li_Id_Type)
      return Identities.Local_Identity_Type
   is
      use type Tkmrpc.Types.Li_Id_Type;
   begin
      for I in Current_Config.L_Identities'Range loop
         if Current_Config.L_Identities (I).Id = Id then
            return Current_Config.L_Identities (I);
         end if;
      end loop;

      raise Config_Error with "No local identity with id " & Id'Img
        & " in config";
   end Get_Local_Identity;

   -------------------------------------------------------------------------

   function Get_Policy
     (Id : Tkmrpc.Types.Sp_Id_Type)
      return Security_Policy_Type
   is
      use type Tkmrpc.Types.Sp_Id_Type;
   begin
      for I in Current_Config.Policies'Range loop
         if Current_Config.Policies (I).Id = Id then
            return Current_Config.Policies (I);
         end if;
      end loop;

      raise Config_Error with "No policy with id " & Id'Img & " in config";
   end Get_Policy;

   -------------------------------------------------------------------------

   function Get_Policy_Count return Natural
   is
   begin
      return Policy_Count;
   end Get_Policy_Count;

   -------------------------------------------------------------------------

   function Is_Empty return Boolean is
      (Policy_Count = 0 and then L_Ident_Count = 0);

   -------------------------------------------------------------------------

   procedure Iterate
     (Process : not null access procedure (Policy : Security_Policy_Type))
   is
   begin
      for I in Current_Config.Policies'First .. Policy_Count loop
         Process (Policy => Current_Config.Policies (I));
      end loop;
   end Iterate;

   -------------------------------------------------------------------------

   procedure Load (Filename : String)
   is
      New_Cfg : constant Config_Type := Read (Filename => Filename);
   begin
      Policy_Count := New_Cfg.Policy_Count;
      Current_Config.Policies (1 .. Policy_Count) := New_Cfg.Policies;
      L_Ident_Count := New_Cfg.Local_Ids_Count;
      Current_Config.L_Identities (1 .. L_Ident_Count) := New_Cfg.L_Identities;
   end Load;

   -------------------------------------------------------------------------

   function Read (Filename : String) return Config_Type
   is
      use type Tkmrpc.Types.Version_Type;
      File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open (File => File,
                        Mode => Ada.Text_IO.In_File,
                        Name => Filename);
      begin
         declare
            Config : constant Config_Type := Config_Type'Input
              (Ada.Text_IO.Text_Streams.Stream (File => File));
         begin
            Ada.Text_IO.Close (File => File);

            if Config.Version /= Version then
               raise Config_Error with "Config version mismatch: '" &
               Filename & "' has" & Config.Version'Img & " instead of" &
               Version'Img;
            end if;

            return Config;
         end;

      exception
         when others =>
            Ada.Text_IO.Close (File => File);
            raise;
      end;

   exception
      when E : others =>
         raise Config_Error with "Unable to read config from file '"
           & Filename & "': " & Ada.Exceptions.Exception_Name (E);
   end Read;

   -------------------------------------------------------------------------

   procedure Write
     (Config   : Config_Type;
      Filename : String)
   is
      File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create
        (File => File,
         Mode => Ada.Text_IO.Out_File,
         Name => Filename);
      Config_Type'Output
        (Ada.Text_IO.Text_Streams.Stream
           (File => File), Config);
      Ada.Text_IO.Close (File => File);

   exception
      when E : others =>
         raise Config_Error with "Unable to write config to file '"
           & Filename & "': " & Ada.Exceptions.Exception_Name (E);
   end Write;

end Tkm.Config;
