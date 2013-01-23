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

with Tkm.Config;

package Tkm.Xfrm
is

   procedure Init;
   --  Init XFRM package.

   procedure Flush;
   --  Flush XFRM policies and states.

   procedure Add_Policy (Policy : Config.Security_Policy_Type);
   --  Add XFRM policy for given security policy.

   procedure Add_State
     (Policy_Id    : Tkmrpc.Types.Sp_Id_Type;
      SPI_In       : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out      : Tkmrpc.Types.Esp_Spi_Type;
      Enc_Key_In   : Tkmrpc.Types.Byte_Sequence;
      Enc_Key_Out  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_In  : Tkmrpc.Types.Byte_Sequence;
      Auth_Key_Out : Tkmrpc.Types.Byte_Sequence);
   --  Add XFRM state for specified policy with given parameters.

   procedure Delete_State
     (Policy_Id : Tkmrpc.Types.Sp_Id_Type;
      SPI_In    : Tkmrpc.Types.Esp_Spi_Type;
      SPI_Out   : Tkmrpc.Types.Esp_Spi_Type);
   --  Delete XFRM state for specified policy with given parameters.

   Xfrm_Error : exception;

end Tkm.Xfrm;
