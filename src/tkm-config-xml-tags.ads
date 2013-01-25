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

package Tkm.Config.Xml.Tags
is

   Policy_Tag      : constant String := "policy";
   Id_Tag          : constant String := "id";
   Local_Tag       : constant String := "local";
   Remote_Tag      : constant String := "remote";
   Ip_Addr_Tag     : constant String := "ip";
   Lifetime_Tag    : constant String := "lifetime";
   Soft_Tag        : constant String := "soft";
   Hard_Tag        : constant String := "hard";
   Identity_Tag    : constant String := "identity";
   Identity_Id_Tag : constant String := "identity_id";
   L_Identity_Tag  : constant String := "local_identity";
   Cert_Tag        : constant String := "certificate";
   Net_Tag         : constant String := "net";
   Mask_Tag        : constant String := "mask";
   Mode_Tag        : constant String := "mode";

end Tkm.Config.Xml.Tags;
