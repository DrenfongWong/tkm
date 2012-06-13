with Ahven.Text_Runner;
with Ahven.Framework;

with Tkm.Logger;

with Random_Tests;

procedure Test_Runner is
   use Ahven.Framework;

   S : constant Test_Suite_Access := Create_Suite (Suite_Name => "TKM tests");
begin
   Tkm.Logger.Use_Stdout;

   Add_Test (Suite => S.all,
             T     => new Random_Tests.Testcase);

   Ahven.Text_Runner.Run (Suite => S);
   Release_Suite (T => S);

   Tkm.Logger.Stop;
end Test_Runner;
