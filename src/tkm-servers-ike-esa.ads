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

with Tkmrpc.Types;

package Tkm.Servers.Ike.Esa
is

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
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters.

   procedure Create_First
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters.

   procedure Create_No_Pfs
     (Esa_Id      : Tkmrpc.Types.Esa_Id_Type;
      Isa_Id      : Tkmrpc.Types.Isa_Id_Type;
      Sp_Id       : Tkmrpc.Types.Sp_Id_Type;
      Ea_Id       : Tkmrpc.Types.Ea_Id_Type;
      Nc_Loc_Id   : Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem   : Tkmrpc.Types.Nonce_Type;
      Initiator   : Tkmrpc.Types.Init_Type;
      Esp_Spi_Loc : Tkmrpc.Types.Esp_Spi_Type;
      Esp_Spi_Rem : Tkmrpc.Types.Esp_Spi_Type);
   --  Create a new ESA context with given id and parameters without perfect
   --  forward secrecy.

   procedure Reset (Esa_Id : Tkmrpc.Types.Esa_Id_Type);
   --  Reset ESA context with given id.

   Policy_Violation : exception;

end Tkm.Servers.Ike.Esa;
