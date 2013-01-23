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

package Tkm.Servers.Ike.Cc
is

   procedure Add_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type);
   --  Add given certificate to certificate chain context specified by id.

   procedure Check_Ca
     (Cc_Id : Tkmrpc.Types.Cc_Id_Type;
      Ca_Id : Tkmrpc.Types.Ca_Id_Type);
   --  Check if specified certificate chain context is based on a trusted CA.

   procedure Set_User_Certificate
     (Cc_Id       : Tkmrpc.Types.Cc_Id_Type;
      Ri_Id       : Tkmrpc.Types.Ri_Id_Type;
      Autha_Id    : Tkmrpc.Types.Autha_Id_Type;
      Certificate : Tkmrpc.Types.Certificate_Type);
   --  Set user certificate for specified certificate chain context.

   procedure Reset (Cc_Id : Tkmrpc.Types.Cc_Id_Type);
   --  Reset certificate chain context with given id.

   Invalid_Certificate : exception;

end Tkm.Servers.Ike.Cc;
