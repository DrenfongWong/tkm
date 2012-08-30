with Tkmrpc.Types;
with Tkmrpc.Results;
with Tkmrpc.Constants;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.Dh;
with Tkmrpc.Contexts.Nc;
with Tkmrpc.Servers.Ike;

package body Server_Ike_Isa_Tests is

   use Ahven;
   use Tkmrpc;

   -------------------------------------------------------------------------

   procedure Check_Isa_Create
   is
      use type Tkmrpc.Results.Result_Type;

      Nonce_Loc     : constant Types.Nonce_Type
        := (Size => 32,
            Data =>
              (16#7a#, 16#33#, 16#d8#, 16#43#, 16#94#, 16#60#, 16#70#, 16#d5#,
               16#5c#, 16#15#, 16#87#, 16#eb#, 16#07#, 16#5c#, 16#b1#, 16#b0#,
               16#7c#, 16#70#, 16#f4#, 16#0b#, 16#d6#, 16#55#, 16#ec#, 16#cd#,
               16#d1#, 16#99#, 16#8a#, 16#5f#, 16#b2#, 16#44#, 16#dd#, 16#93#,
               others => 0));
      Nonce_Rem     : constant Types.Nonce_Type
        := (Size => 32,
            Data =>
              (16#d7#, 16#41#, 16#80#, 16#82#, 16#9e#, 16#f7#, 16#87#, 16#d5#,
               16#54#, 16#15#, 16#0c#, 16#9e#, 16#3f#, 16#86#, 16#26#, 16#81#,
               16#bd#, 16#2f#, 16#8d#, 16#d0#, 16#9c#, 16#d3#, 16#55#, 16#cf#,
               16#dc#, 16#36#, 16#d3#, 16#ce#, 16#3c#, 16#98#, 16#eb#, 16#da#,
               others => 0));
      Shared_Secret : constant Types.Dh_Key_Type
        := (Size => 512,
            Data =>
              (16#2c#, 16#bb#, 16#82#, 16#6d#, 16#88#, 16#7e#, 16#32#, 16#26#,
               16#63#, 16#b9#, 16#f8#, 16#36#, 16#78#, 16#29#, 16#06#, 16#0a#,
               16#c0#, 16#1c#, 16#99#, 16#b1#, 16#12#, 16#02#, 16#e9#, 16#07#,
               16#e1#, 16#24#, 16#6e#, 16#c2#, 16#05#, 16#18#, 16#81#, 16#4f#,
               16#21#, 16#eb#, 16#b2#, 16#66#, 16#d0#, 16#67#, 16#b8#, 16#e0#,
               16#27#, 16#27#, 16#11#, 16#07#, 16#02#, 16#7c#, 16#f7#, 16#e8#,
               16#65#, 16#b9#, 16#2c#, 16#5b#, 16#6c#, 16#8a#, 16#06#, 16#95#,
               16#71#, 16#a1#, 16#2c#, 16#92#, 16#cc#, 16#a3#, 16#d0#, 16#62#,
               16#e1#, 16#6b#, 16#37#, 16#a6#, 16#73#, 16#d3#, 16#25#, 16#36#,
               16#f5#, 16#ed#, 16#4e#, 16#84#, 16#8d#, 16#6e#, 16#56#, 16#0a#,
               16#ef#, 16#c5#, 16#f9#, 16#1b#, 16#74#, 16#57#, 16#00#, 16#9b#,
               16#ec#, 16#bd#, 16#af#, 16#94#, 16#96#, 16#d3#, 16#19#, 16#ed#,
               16#dc#, 16#11#, 16#a5#, 16#90#, 16#a3#, 16#59#, 16#ed#, 16#32#,
               16#86#, 16#14#, 16#0f#, 16#57#, 16#9e#, 16#89#, 16#35#, 16#41#,
               16#33#, 16#4c#, 16#f3#, 16#27#, 16#23#, 16#f4#, 16#ee#, 16#d4#,
               16#4a#, 16#fd#, 16#23#, 16#0e#, 16#26#, 16#f1#, 16#4d#, 16#9d#,
               16#81#, 16#65#, 16#b3#, 16#c5#, 16#1d#, 16#c4#, 16#98#, 16#44#,
               16#ad#, 16#8f#, 16#62#, 16#29#, 16#c5#, 16#9d#, 16#b4#, 16#e2#,
               16#ee#, 16#89#, 16#bc#, 16#82#, 16#30#, 16#73#, 16#73#, 16#9c#,
               16#f4#, 16#0c#, 16#25#, 16#2a#, 16#ff#, 16#e3#, 16#bb#, 16#be#,
               16#c7#, 16#1c#, 16#5e#, 16#12#, 16#cf#, 16#be#, 16#4b#, 16#47#,
               16#37#, 16#ac#, 16#c0#, 16#f4#, 16#2c#, 16#b0#, 16#1c#, 16#59#,
               16#c6#, 16#c7#, 16#cf#, 16#b7#, 16#2f#, 16#b5#, 16#55#, 16#7f#,
               16#2d#, 16#21#, 16#f0#, 16#fa#, 16#d7#, 16#ff#, 16#80#, 16#2b#,
               16#17#, 16#d7#, 16#06#, 16#89#, 16#30#, 16#0c#, 16#97#, 16#dd#,
               16#71#, 16#20#, 16#be#, 16#ee#, 16#d0#, 16#85#, 16#3d#, 16#ba#,
               16#d6#, 16#58#, 16#6c#, 16#be#, 16#db#, 16#1c#, 16#29#, 16#9d#,
               16#00#, 16#79#, 16#61#, 16#b1#, 16#50#, 16#98#, 16#14#, 16#d7#,
               16#aa#, 16#18#, 16#ad#, 16#7e#, 16#f5#, 16#1a#, 16#df#, 16#60#,
               16#b4#, 16#82#, 16#3f#, 16#bf#, 16#49#, 16#93#, 16#0f#, 16#6e#,
               16#21#, 16#27#, 16#e7#, 16#a5#, 16#59#, 16#b9#, 16#95#, 16#ab#,
               16#af#, 16#3d#, 16#94#, 16#02#, 16#41#, 16#f3#, 16#53#, 16#03#,
               16#19#, 16#2c#, 16#47#, 16#14#, 16#4d#, 16#69#, 16#eb#, 16#16#,
               16#a3#, 16#5a#, 16#a4#, 16#24#, 16#0d#, 16#58#, 16#7c#, 16#ce#,
               16#52#, 16#a5#, 16#83#, 16#1c#, 16#d1#, 16#c8#, 16#a0#, 16#ce#,
               16#bd#, 16#73#, 16#28#, 16#9b#, 16#f6#, 16#ba#, 16#e7#, 16#46#,
               16#e6#, 16#5e#, 16#64#, 16#ef#, 16#60#, 16#08#, 16#cd#, 16#30#,
               16#b9#, 16#78#, 16#4c#, 16#61#, 16#a0#, 16#cd#, 16#ba#, 16#1e#,
               16#0b#, 16#77#, 16#74#, 16#a4#, 16#70#, 16#91#, 16#13#, 16#bf#,
               16#f0#, 16#c5#, 16#17#, 16#b6#, 16#aa#, 16#aa#, 16#1e#, 16#31#,
               16#15#, 16#e8#, 16#5e#, 16#72#, 16#93#, 16#e5#, 16#98#, 16#93#,
               16#30#, 16#e5#, 16#9b#, 16#9a#, 16#d4#, 16#d4#, 16#a3#, 16#0e#,
               16#74#, 16#bc#, 16#ae#, 16#41#, 16#61#, 16#bd#, 16#33#, 16#14#,
               16#0b#, 16#2b#, 16#5b#, 16#7e#, 16#3e#, 16#ca#, 16#2e#, 16#c6#,
               16#53#, 16#a6#, 16#44#, 16#da#, 16#95#, 16#58#, 16#be#, 16#24#,
               16#ec#, 16#09#, 16#20#, 16#ad#, 16#3b#, 16#95#, 16#d1#, 16#2f#,
               16#ad#, 16#11#, 16#11#, 16#f0#, 16#7e#, 16#a6#, 16#b9#, 16#17#,
               16#b9#, 16#8b#, 16#6a#, 16#b2#, 16#a0#, 16#40#, 16#6a#, 16#0f#,
               16#e1#, 16#a3#, 16#0f#, 16#ef#, 16#0e#, 16#6c#, 16#f4#, 16#3c#,
               16#36#, 16#91#, 16#19#, 16#60#, 16#c7#, 16#1f#, 16#44#, 16#b0#,
               16#22#, 16#49#, 16#a9#, 16#6e#, 16#5d#, 16#9b#, 16#43#, 16#08#,
               16#52#, 16#fe#, 16#23#, 16#4b#, 16#06#, 16#e9#, 16#b2#, 16#c1#,
               16#87#, 16#fa#, 16#12#, 16#56#, 16#f2#, 16#6d#, 16#64#, 16#06#,
               16#9e#, 16#0e#, 16#de#, 16#ed#, 16#2f#, 16#0f#, 16#78#, 16#d9#,
               16#26#, 16#b8#, 16#1c#, 16#7e#, 16#ab#, 16#8d#, 16#7d#, 16#96#,
               16#70#, 16#55#, 16#f5#, 16#6b#, 16#bc#, 16#a1#, 16#36#, 16#b6#,
               16#3d#, 16#ae#, 16#9f#, 16#00#, 16#33#, 16#e9#, 16#13#, 16#ea#,
               16#83#, 16#f2#, 16#d1#, 16#36#, 16#bb#, 16#21#, 16#62#, 16#d5#,
               16#e4#, 16#fd#, 16#87#, 16#d4#, 16#84#, 16#2a#, 16#49#, 16#6a#,
               16#d4#, 16#69#, 16#ce#, 16#04#, 16#70#, 16#43#, 16#87#, 16#b7#,
               16#41#, 16#14#, 16#d5#, 16#90#, 16#05#, 16#98#, 16#87#, 16#a7#,
               16#c7#, 16#fe#, 16#8e#, 16#ca#, 16#3d#, 16#ad#, 16#2a#, 16#fa#,
               16#cb#, 16#d3#, 16#5a#, 16#bf#, 16#e6#, 16#c7#, 16#16#, 16#d7#,
               16#94#, 16#1f#, 16#91#, 16#db#, 16#1e#, 16#70#, 16#3f#, 16#85#
              ));
      Ref_Sk_Ai     : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#ea#, 16#61#, 16#4b#, 16#d8#, 16#3b#, 16#0e#, 16#af#, 16#d5#,
               16#16#, 16#98#, 16#41#, 16#a3#, 16#d4#, 16#50#, 16#43#, 16#42#,
               16#94#, 16#5e#, 16#32#, 16#5c#, 16#f9#, 16#7f#, 16#ab#, 16#1b#,
               16#59#, 16#29#, 16#d8#, 16#d0#, 16#55#, 16#f8#, 16#7d#, 16#bd#,
               16#b3#, 16#8e#, 16#95#, 16#fe#, 16#86#, 16#86#, 16#3b#, 16#7d#,
               16#7e#, 16#e2#, 16#8f#, 16#1d#, 16#65#, 16#eb#, 16#8b#, 16#07#,
               16#a3#, 16#c9#, 16#7a#, 16#25#, 16#ff#, 16#99#, 16#92#, 16#94#,
               16#d7#, 16#88#, 16#45#, 16#73#, 16#5f#, 16#47#, 16#c1#, 16#9e#,
               others => 0));
      Ref_Sk_Ar     : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#cc#, 16#30#, 16#7a#, 16#af#, 16#4a#, 16#06#, 16#8c#, 16#2c#,
               16#e8#, 16#69#, 16#02#, 16#23#, 16#82#, 16#d5#, 16#55#, 16#cd#,
               16#cc#, 16#fd#, 16#3e#, 16#c4#, 16#f9#, 16#46#, 16#6b#, 16#4d#,
               16#da#, 16#8e#, 16#18#, 16#d1#, 16#21#, 16#a0#, 16#9c#, 16#19#,
               16#3a#, 16#21#, 16#3e#, 16#c0#, 16#9d#, 16#76#, 16#42#, 16#18#,
               16#4a#, 16#2a#, 16#7a#, 16#d0#, 16#e5#, 16#c1#, 16#95#, 16#e0#,
               16#26#, 16#2e#, 16#5c#, 16#c8#, 16#df#, 16#3a#, 16#53#, 16#38#,
               16#6e#, 16#01#, 16#46#, 16#f1#, 16#8f#, 16#38#, 16#e8#, 16#7f#,
               others => 0));
      Ref_Sk_Ei     : constant Types.Key_Type
        := (Size => 32,
            Data =>
              (16#51#, 16#12#, 16#24#, 16#cc#, 16#78#, 16#c0#, 16#c4#, 16#69#,
               16#89#, 16#65#, 16#07#, 16#2c#, 16#58#, 16#d5#, 16#99#, 16#a9#,
               16#09#, 16#3c#, 16#f1#, 16#a6#, 16#8a#, 16#45#, 16#f3#, 16#00#,
               16#d1#, 16#d8#, 16#ba#, 16#31#, 16#5c#, 16#6b#, 16#3b#, 16#d4#,
               others => 0));
      Ref_Sk_Er     : constant Types.Key_Type
        := (Size => 32,
            Data =>
              (16#96#, 16#55#, 16#e7#, 16#66#, 16#70#, 16#52#, 16#67#, 16#45#,
               16#b3#, 16#2a#, 16#06#, 16#3d#, 16#7c#, 16#a7#, 16#01#, 16#7b#,
               16#80#, 16#ad#, 16#f6#, 16#b9#, 16#25#, 16#46#, 16#64#, 16#80#,
               16#1d#, 16#90#, 16#7d#, 16#10#, 16#9f#, 16#3e#, 16#4e#, 16#58#,
               others => 0));
      Res           : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Contexts.Dh.Create (Id       => 1,
                          Dha_Id   => Constants.Modp_4096,
                          Secvalue => Types.Null_Dh_Priv_Type);
      Contexts.Dh.Generate (Id        => 1,
                            Dh_Key    => Shared_Secret,
                            Timestamp => 0);
      Contexts.Nc.Create (Id    => 1,
                          Nonce => Nonce_Loc);
      declare
         use type Tkmrpc.Types.Key_Type;

         Sk_Ai, Sk_Ar, Sk_Ei, Sk_Er : Types.Key_Type;
      begin
         Servers.Ike.Isa_Create
           (Result    => Res,
            Isa_Id    => 1,
            Ae_Id     => 1,
            Ia_Id     => 1,
            Dh_Id     => 1,
            Nc_Loc_Id => 1,
            Nonce_Rem => Nonce_Rem,
            Initiator => 1,
            Spi_Loc   => 17351007588898857637,
            Spi_Rem   => 3862768849451712992,
            Sk_Ai     => Sk_Ai,
            Sk_Ar     => Sk_Ar,
            Sk_Ei     => Sk_Ei,
            Sk_Er     => Sk_Er);
         Assert (Condition => Res = Results.Ok,
                 Message   => "Isa_Create failed");

         Assert (Condition => Sk_Ai = Ref_Sk_Ai,
                 Message   => "Sk_Ai mismatch");
         Assert (Condition => Sk_Ar = Ref_Sk_Ar,
                 Message   => "Sk_Ar mismatch");
         Assert (Condition => Sk_Ei = Ref_Sk_Ei,
                 Message   => "Sk_Ei mismatch");
         Assert (Condition => Sk_Er = Ref_Sk_Er,
                 Message   => "Sk_Er mismatch");
      end;

      Assert (Condition => Contexts.isa.Has_State
              (Id    => 1,
               State => Contexts.isa.active),
              Message   => "ISA context not 'active'");
      Assert (Condition => Contexts.ae.Has_State
              (Id    => 1,
               State => Contexts.ae.unauth),
              Message   => "AE context not 'unauth'");
      Assert (Condition => Contexts.Nc.Has_State
              (Id    => 1,
               State => Contexts.Nc.Clean),
              Message   => "Nc context not 'clean'");
      --           Assert (Condition => Contexts.Dh.Has_State
      --                   (Id    => 1,
      --                    State => Contexts.Dh.Clean),
      --                   Message   => "Dh context state mismatch");

      Servers.Ike.Isa_Reset (Result => Res,
                             Isa_Id => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Isa_Reset failed");
      Assert (Condition => Contexts.isa.Has_State
              (Id    => 1,
               State => Contexts.isa.clean),
              Message   => "ISA context not 'clean'");

      --  DH context must be reset explicitly since it is currently not
      --  consumed.

      Servers.Ike.Dh_Reset (Result => Res,
                            Dh_Id  => 1);
      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Isa_Reset (Result => Res,
                                Isa_Id => 1);
         Servers.Ike.Nc_Reset (Result => Res,
                               Nc_Id  => 1);
         Servers.Ike.Dh_Reset (Result => Res,
                               Dh_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Isa_Create;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server ISA tests");
      T.Add_Test_Routine
        (Routine => Check_Isa_Create'Access,
         Name    => "Check Isa_Create");
   end Initialize;

end Server_Ike_Isa_Tests;
