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

package Tkm.Servers.Ike.Isa
is

   procedure Create
     (Isa_Id    :     Tkmrpc.Types.Isa_Id_Type;
      Ae_Id     :     Tkmrpc.Types.Ae_Id_Type;
      Ia_Id     :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id     :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem :     Tkmrpc.Types.Nonce_Type;
      Initiator :     Tkmrpc.Types.Init_Type;
      Spi_Loc   :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem   :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai     : out Tkmrpc.Types.Key_Type;
      Sk_Ar     : out Tkmrpc.Types.Key_Type;
      Sk_Ei     : out Tkmrpc.Types.Key_Type;
      Sk_Er     : out Tkmrpc.Types.Key_Type);
   --  Create a new ISA context with given id and parameters. Return the
   --  computed authentication and encryption keys.

   procedure Create_Child
     (Isa_Id        :     Tkmrpc.Types.Isa_Id_Type;
      Parent_Isa_Id :     Tkmrpc.Types.Isa_Id_Type;
      Ia_Id         :     Tkmrpc.Types.Ia_Id_Type;
      Dh_Id         :     Tkmrpc.Types.Dh_Id_Type;
      Nc_Loc_Id     :     Tkmrpc.Types.Nc_Id_Type;
      Nonce_Rem     :     Tkmrpc.Types.Nonce_Type;
      Initiator     :     Tkmrpc.Types.Init_Type;
      Spi_Loc       :     Tkmrpc.Types.Ike_Spi_Type;
      Spi_Rem       :     Tkmrpc.Types.Ike_Spi_Type;
      Sk_Ai         : out Tkmrpc.Types.Key_Type;
      Sk_Ar         : out Tkmrpc.Types.Key_Type;
      Sk_Ei         : out Tkmrpc.Types.Key_Type;
      Sk_Er         : out Tkmrpc.Types.Key_Type);
   --  Rekey a ISA by creating a new ISA context with given id and parameters.
   --  Return the computed authentication and encryption keys.

   procedure Sign
     (Isa_Id       :     Tkmrpc.Types.Isa_Id_Type;
      Lc_Id        :     Tkmrpc.Types.Lc_Id_Type;
      Init_Message :     Tkmrpc.Types.Init_Message_Type;
      Signature    : out Tkmrpc.Types.Signature_Type);
   --  Create signature of local authentication octets using given message.

   procedure Auth
     (Isa_Id       : Tkmrpc.Types.Isa_Id_Type;
      Cc_Id        : Tkmrpc.Types.Cc_Id_Type;
      Init_Message : Tkmrpc.Types.Init_Message_Type;
      Signature    : Tkmrpc.Types.Signature_Type);
   --  Authenticate ISA context identified by id with specified cc context, IKE
   --  init message and given signature.

   procedure Reset (Isa_Id : Tkmrpc.Types.Isa_Id_Type);
   --  Reset ISA context with given id.

   procedure Skip_Create_First (Isa_Id : Tkmrpc.Types.Isa_Id_Type);
   --  Skip creation of first child SA.

   Authentication_Failure : exception;

end Tkm.Servers.Ike.Isa;
