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

with Ada.Command_Line;

with Ahven.Text_Runner;
with Ahven.Framework;

with Tkm.Logger;

with Assertion_Tests;
with Exceptions_Tests;
with Random_Tests;
with Locked_Mem_Tests;
with Util_Tests;
with Config_Tests;
with Identity_Tests;
with Diffie_Hellman_Tests;
with Hmac_Tests;
with Prf_Plus_Tests;
with Signer_Tests;
with Key_Derivation_Tests;
with Private_Key_Tests;
with Cacert_Tests;
with Server_Ike_Nonce_Tests;
with Server_Ike_DH_Tests;
with Server_Ike_Tkm_Tests;
with Server_Ike_Isa_Tests;
with Server_Ike_Ae_Tests;
with Server_Ike_Cc_Tests;

procedure Test_Runner is
   use Ahven.Framework;

   S : constant Test_Suite_Access := Create_Suite (Suite_Name => "TKM tests");
begin
   Tkm.Logger.Use_File (Path => Ada.Command_Line.Command_Name & ".log");

   Add_Test (Suite => S.all,
             T     => new Assertion_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Exceptions_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Random_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Locked_Mem_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Util_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Identity_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Config_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Diffie_Hellman_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Hmac_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Prf_Plus_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Signer_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Key_Derivation_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Private_Key_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Cacert_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Nonce_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_DH_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Tkm_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Isa_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Ae_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Cc_Tests.Testcase);

   Ahven.Text_Runner.Run (Suite => S);
   Release_Suite (T => S);

   Tkm.Logger.Stop;
end Test_Runner;
