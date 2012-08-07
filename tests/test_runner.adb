with Ahven.Text_Runner;
with Ahven.Framework;

with Tkm.Logger;

with Assertion_Tests;
with Random_Tests;
with Locked_Mem_Tests;
with Util_Tests;
with Diffie_Hellman_Tests;
with Server_Ike_Nonce_Tests;
with Server_Ike_DH_Tests;
with Server_Ike_Tkm_Tests;

procedure Test_Runner is
   use Ahven.Framework;

   S : constant Test_Suite_Access := Create_Suite (Suite_Name => "TKM tests");
begin
   Tkm.Logger.Use_Stdout;

   Add_Test (Suite => S.all,
             T     => new Assertion_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Random_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Locked_Mem_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Util_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Diffie_Hellman_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Nonce_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_DH_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Server_Ike_Tkm_Tests.Testcase);

   Ahven.Text_Runner.Run (Suite => S);
   Release_Suite (T => S);

   Tkm.Logger.Stop;
end Test_Runner;
