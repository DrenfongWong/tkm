--
--  Copyright (C) 2011  Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2011  Adrian-Ken Rueegsegger <ken@codelabs.ch>
--
--  This program is free software; you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the
--  Free Software Foundation; either version 2 of the License, or (at your
--  option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
--
--  This program is distributed in the hope that it will be useful, but
--  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
--  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
--  for more details.
--

with Ada.Interrupts.Names;

package body Tkm.Termination
is

   protected Exit_Signal_Handler is
      entry Wait_Signal (Status : out Status_Type);
      procedure Fire (Status : Status_Type);
   private
      procedure Handle_Sigterm;
      pragma Attach_Handler (Handle_Sigterm, Ada.Interrupts.Names.SIGTERM);

      Exit_Status : Status_Type;
      Fired       : Boolean := False;
   end Exit_Signal_Handler;

   Status_Map : constant array (Status_Type) of Ada.Command_Line.Exit_Status
     := (Success => Ada.Command_Line.Success,
         Failure => Ada.Command_Line.Failure);
   --  Mapping of status type values to command line exit codes.

   -------------------------------------------------------------------------

   protected body Exit_Signal_Handler is

      ----------------------------------------------------------------------

      procedure Fire (Status : Status_Type)
      is
      begin
         Exit_Status := Status;
         Fired       := True;
      end Fire;

      ----------------------------------------------------------------------

      procedure Handle_Sigterm
      is
      begin
         Fired       := True;
         Exit_Status := Success;
      end Handle_Sigterm;

      ----------------------------------------------------------------------

      entry Wait_Signal (Status : out Status_Type)
        when Fired
      is
      begin
         Status := Exit_Status;

         if Wait_Signal'Count = 0 then
            Fired := False;
         end if;
      end Wait_Signal;

   end Exit_Signal_Handler;

   -------------------------------------------------------------------------

   procedure Signal (Exit_Status : Status_Type)
   is
   begin
      Exit_Signal_Handler.Fire (Status => Exit_Status);
   end Signal;

   -------------------------------------------------------------------------

   function Wait return Ada.Command_Line.Exit_Status
   is
      S : Status_Type;
   begin
      Exit_Signal_Handler.Wait_Signal (Status => S);
      return Status_Map (S);
   end Wait;

end Tkm.Termination;
