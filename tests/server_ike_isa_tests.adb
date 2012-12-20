with Tkmrpc.Types;
with Tkmrpc.Results;
with Tkmrpc.Constants;
with Tkmrpc.Contexts.isa;
with Tkmrpc.Contexts.ae;
with Tkmrpc.Contexts.dh;
with Tkmrpc.Contexts.nc;
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
      Contexts.dh.create
        (Id       => 1,
         dha_id   => Tkmrpc.Types.Dha_Id_Type (Constants.Modp_4096),
         secvalue => Types.Null_Dh_Priv_Type);
      Contexts.dh.generate (Id        => 1,
                            dh_key    => Shared_Secret,
                            timestamp => 0);
      Contexts.nc.create (Id    => 1,
                          nonce => Nonce_Loc);
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
      Assert (Condition => Contexts.nc.Has_State
              (Id    => 1,
               State => Contexts.nc.clean),
              Message   => "Nc context not 'clean'");
      Assert (Condition => Contexts.dh.Has_State
              (Id    => 1,
               State => Contexts.dh.clean),
              Message   => "Dh context state mismatch");

      Servers.Ike.Isa_Reset (Result => Res,
                             Isa_Id => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Isa_Reset failed");
      Assert (Condition => Contexts.isa.Has_State
              (Id    => 1,
               State => Contexts.isa.clean),
              Message   => "ISA context not 'clean'");

      Servers.Ike.Ae_Reset (Result => Res,
                            Ae_Id  => 1);

      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Isa_Reset (Result => Res,
                                Isa_Id => 1);
         Servers.Ike.Ae_Reset (Result => Res,
                               Ae_Id  => 1);
         Servers.Ike.Nc_Reset (Result => Res,
                               Nc_Id  => 1);
         Servers.Ike.Dh_Reset (Result => Res,
                               Dh_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Isa_Create;

   -------------------------------------------------------------------------

   procedure Check_Isa_Create_Child
   is
      use type Tkmrpc.Results.Result_Type;

      Parent_Sk_D   : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#24#, 16#4c#, 16#ef#, 16#46#, 16#c8#, 16#fd#, 16#17#, 16#31#,
               16#d1#, 16#8e#, 16#01#, 16#90#, 16#63#, 16#1d#, 16#87#, 16#19#,
               16#ba#, 16#a1#, 16#1f#, 16#59#, 16#84#, 16#14#, 16#e3#, 16#5b#,
               16#fd#, 16#14#, 16#94#, 16#ca#, 16#df#, 16#ed#, 16#29#, 16#96#,
               16#d8#, 16#0a#, 16#0d#, 16#18#, 16#15#, 16#4a#, 16#94#, 16#ab#,
               16#fa#, 16#bb#, 16#56#, 16#f2#, 16#4e#, 16#51#, 16#bd#, 16#dd#,
               16#04#, 16#58#, 16#59#, 16#34#, 16#04#, 16#fd#, 16#b6#, 16#4a#,
               16#45#, 16#67#, 16#59#, 16#06#, 16#90#, 16#d5#, 16#7d#, 16#20#,
               others => 0));
      Nonce_Loc     : constant Types.Nonce_Type
        := (Size => 32,
            Data =>
              (16#d8#, 16#d1#, 16#72#, 16#09#, 16#29#, 16#37#, 16#cb#, 16#17#,
               16#8d#, 16#44#, 16#4e#, 16#54#, 16#99#, 16#1e#, 16#81#, 16#47#,
               16#42#, 16#db#, 16#59#, 16#17#, 16#ad#, 16#04#, 16#c2#, 16#ba#,
               16#6e#, 16#b1#, 16#6d#, 16#7f#, 16#70#, 16#e6#, 16#2b#, 16#03#,
               others => 0));
      Nonce_Rem     : constant Types.Nonce_Type
        := (Size => 32,
            Data =>
              (16#fb#, 16#13#, 16#bb#, 16#2e#, 16#d2#, 16#6f#, 16#28#, 16#47#,
               16#95#, 16#0f#, 16#ca#, 16#2b#, 16#0f#, 16#c7#, 16#fd#, 16#27#,
               16#84#, 16#b3#, 16#bb#, 16#d3#, 16#d6#, 16#26#, 16#84#, 16#5f#,
               16#ee#, 16#37#, 16#64#, 16#07#, 16#fb#, 16#fd#, 16#c0#, 16#ca#,
               others => 0));
      Shared_Secret : constant Types.Dh_Key_Type
        := (Size => 512,
            Data =>
              (16#fb#, 16#cd#, 16#a9#, 16#7f#, 16#a0#, 16#70#, 16#c0#, 16#6b#,
               16#95#, 16#20#, 16#db#, 16#61#, 16#9d#, 16#db#, 16#be#, 16#ba#,
               16#ee#, 16#f5#, 16#ef#, 16#ea#, 16#20#, 16#ba#, 16#e7#, 16#08#,
               16#4c#, 16#ab#, 16#9a#, 16#9a#, 16#5b#, 16#90#, 16#7b#, 16#b0#,
               16#42#, 16#ff#, 16#af#, 16#1c#, 16#18#, 16#4b#, 16#f9#, 16#63#,
               16#27#, 16#fa#, 16#f1#, 16#71#, 16#cb#, 16#a9#, 16#28#, 16#9d#,
               16#c7#, 16#61#, 16#f1#, 16#ba#, 16#8f#, 16#3e#, 16#75#, 16#70#,
               16#30#, 16#97#, 16#78#, 16#10#, 16#3f#, 16#b8#, 16#bf#, 16#6e#,
               16#b8#, 16#b0#, 16#a5#, 16#5a#, 16#3b#, 16#7a#, 16#78#, 16#d9#,
               16#1e#, 16#32#, 16#56#, 16#68#, 16#38#, 16#8e#, 16#a7#, 16#27#,
               16#ee#, 16#e8#, 16#79#, 16#00#, 16#ec#, 16#be#, 16#b4#, 16#01#,
               16#d2#, 16#6a#, 16#1e#, 16#73#, 16#5e#, 16#72#, 16#bd#, 16#7f#,
               16#a8#, 16#dc#, 16#b4#, 16#d1#, 16#8c#, 16#9a#, 16#c2#, 16#1e#,
               16#e5#, 16#db#, 16#58#, 16#ac#, 16#7c#, 16#8f#, 16#6f#, 16#4b#,
               16#81#, 16#8d#, 16#90#, 16#fa#, 16#9d#, 16#d6#, 16#e6#, 16#15#,
               16#9e#, 16#f3#, 16#7b#, 16#e4#, 16#25#, 16#ce#, 16#f6#, 16#e5#,
               16#05#, 16#b1#, 16#c0#, 16#cf#, 16#f8#, 16#ef#, 16#35#, 16#30#,
               16#fe#, 16#54#, 16#69#, 16#1a#, 16#c5#, 16#42#, 16#98#, 16#5c#,
               16#5a#, 16#ec#, 16#a0#, 16#17#, 16#c6#, 16#fb#, 16#73#, 16#97#,
               16#8e#, 16#43#, 16#5c#, 16#79#, 16#2c#, 16#6f#, 16#04#, 16#01#,
               16#85#, 16#9f#, 16#fa#, 16#b3#, 16#17#, 16#8d#, 16#41#, 16#3f#,
               16#34#, 16#50#, 16#04#, 16#ed#, 16#b1#, 16#20#, 16#e5#, 16#90#,
               16#19#, 16#76#, 16#17#, 16#21#, 16#5b#, 16#9d#, 16#49#, 16#9e#,
               16#ed#, 16#26#, 16#df#, 16#d3#, 16#bf#, 16#f0#, 16#ab#, 16#4b#,
               16#b1#, 16#ce#, 16#8c#, 16#d1#, 16#e8#, 16#69#, 16#49#, 16#4e#,
               16#94#, 16#70#, 16#f2#, 16#8a#, 16#bf#, 16#8f#, 16#10#, 16#c7#,
               16#94#, 16#be#, 16#57#, 16#91#, 16#b5#, 16#43#, 16#05#, 16#9e#,
               16#9d#, 16#87#, 16#23#, 16#29#, 16#6d#, 16#52#, 16#e5#, 16#1c#,
               16#9c#, 16#da#, 16#6e#, 16#5e#, 16#ed#, 16#a8#, 16#a4#, 16#78#,
               16#53#, 16#97#, 16#3b#, 16#e4#, 16#3c#, 16#3d#, 16#1c#, 16#69#,
               16#6e#, 16#be#, 16#b4#, 16#38#, 16#19#, 16#2c#, 16#2a#, 16#8a#,
               16#b4#, 16#23#, 16#6c#, 16#60#, 16#1a#, 16#78#, 16#db#, 16#e4#,
               16#b3#, 16#e6#, 16#a6#, 16#f0#, 16#3b#, 16#2d#, 16#9e#, 16#d9#,
               16#7f#, 16#e0#, 16#1e#, 16#86#, 16#cb#, 16#64#, 16#4a#, 16#62#,
               16#fd#, 16#33#, 16#ee#, 16#5e#, 16#7f#, 16#95#, 16#4a#, 16#b2#,
               16#30#, 16#27#, 16#f4#, 16#55#, 16#f6#, 16#72#, 16#6c#, 16#1a#,
               16#ce#, 16#49#, 16#7c#, 16#49#, 16#9f#, 16#e6#, 16#f3#, 16#b7#,
               16#57#, 16#f7#, 16#d6#, 16#16#, 16#b7#, 16#b1#, 16#7d#, 16#85#,
               16#a3#, 16#99#, 16#06#, 16#c6#, 16#5d#, 16#7c#, 16#3f#, 16#b6#,
               16#66#, 16#6b#, 16#2b#, 16#03#, 16#c0#, 16#0c#, 16#0f#, 16#80#,
               16#0a#, 16#ac#, 16#f3#, 16#ef#, 16#02#, 16#e5#, 16#4c#, 16#77#,
               16#52#, 16#02#, 16#80#, 16#f2#, 16#41#, 16#1e#, 16#8e#, 16#4c#,
               16#05#, 16#f8#, 16#4b#, 16#f5#, 16#24#, 16#82#, 16#bf#, 16#70#,
               16#07#, 16#60#, 16#1b#, 16#9b#, 16#48#, 16#73#, 16#b8#, 16#9a#,
               16#1f#, 16#44#, 16#7c#, 16#28#, 16#26#, 16#f3#, 16#8d#, 16#bd#,
               16#2b#, 16#78#, 16#5f#, 16#81#, 16#34#, 16#0b#, 16#20#, 16#5c#,
               16#14#, 16#1a#, 16#52#, 16#96#, 16#22#, 16#86#, 16#a1#, 16#e0#,
               16#d5#, 16#7f#, 16#15#, 16#78#, 16#90#, 16#06#, 16#08#, 16#39#,
               16#b1#, 16#32#, 16#cf#, 16#77#, 16#4b#, 16#7a#, 16#85#, 16#2d#,
               16#b9#, 16#f6#, 16#f3#, 16#db#, 16#e2#, 16#39#, 16#9d#, 16#e6#,
               16#9c#, 16#80#, 16#d2#, 16#03#, 16#c8#, 16#da#, 16#00#, 16#d3#,
               16#5b#, 16#bc#, 16#51#, 16#3a#, 16#c8#, 16#a3#, 16#f2#, 16#dc#,
               16#8c#, 16#55#, 16#0f#, 16#c4#, 16#52#, 16#e1#, 16#cc#, 16#ce#,
               16#7c#, 16#9c#, 16#52#, 16#a1#, 16#c4#, 16#db#, 16#8e#, 16#6d#,
               16#9a#, 16#66#, 16#1b#, 16#67#, 16#cd#, 16#14#, 16#c5#, 16#3e#,
               16#78#, 16#5c#, 16#66#, 16#9d#, 16#bc#, 16#09#, 16#19#, 16#c1#,
               16#3d#, 16#72#, 16#07#, 16#25#, 16#7a#, 16#4a#, 16#bd#, 16#24#,
               16#50#, 16#cc#, 16#bd#, 16#a4#, 16#b5#, 16#32#, 16#19#, 16#ef#,
               16#72#, 16#3f#, 16#a3#, 16#79#, 16#92#, 16#2e#, 16#fe#, 16#63#,
               16#4d#, 16#e1#, 16#53#, 16#d2#, 16#3e#, 16#19#, 16#31#, 16#23#,
               16#ed#, 16#f8#, 16#f8#, 16#41#, 16#7b#, 16#33#, 16#03#, 16#cc#,
               16#90#, 16#c6#, 16#55#, 16#7a#, 16#0d#, 16#9a#, 16#39#, 16#ff#,
               16#a9#, 16#38#, 16#23#, 16#45#, 16#b9#, 16#e7#, 16#1c#, 16#76#,
               16#c5#, 16#76#, 16#20#, 16#21#, 16#8c#, 16#9d#, 16#ea#, 16#fe#
              ));
      Ref_Sk_D      : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#84#, 16#f6#, 16#da#, 16#54#, 16#01#, 16#3d#, 16#67#, 16#bd#,
               16#d7#, 16#a1#, 16#fa#, 16#36#, 16#5c#, 16#63#, 16#d9#, 16#24#,
               16#c7#, 16#4b#, 16#50#, 16#d1#, 16#00#, 16#b7#, 16#db#, 16#24#,
               16#cb#, 16#bc#, 16#27#, 16#44#, 16#f6#, 16#63#, 16#15#, 16#94#,
               16#a5#, 16#8c#, 16#6f#, 16#d9#, 16#4b#, 16#72#, 16#1d#, 16#5c#,
               16#6d#, 16#3f#, 16#84#, 16#81#, 16#5c#, 16#b7#, 16#46#, 16#f9#,
               16#f9#, 16#42#, 16#01#, 16#eb#, 16#6c#, 16#0f#, 16#81#, 16#cc#,
               16#72#, 16#b5#, 16#af#, 16#63#, 16#39#, 16#06#, 16#3a#, 16#bf#,
               others => 0));
      Ref_Sk_Ai     : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#e0#, 16#0a#, 16#32#, 16#77#, 16#c4#, 16#80#, 16#c3#, 16#df#,
               16#ca#, 16#54#, 16#23#, 16#a0#, 16#bf#, 16#04#, 16#3e#, 16#ec#,
               16#52#, 16#0b#, 16#ce#, 16#76#, 16#65#, 16#af#, 16#2a#, 16#0f#,
               16#6c#, 16#b3#, 16#08#, 16#de#, 16#b2#, 16#ba#, 16#e9#, 16#59#,
               16#3a#, 16#2a#, 16#06#, 16#99#, 16#aa#, 16#e3#, 16#e8#, 16#b9#,
               16#b1#, 16#70#, 16#d9#, 16#a2#, 16#0c#, 16#98#, 16#3f#, 16#4c#,
               16#1a#, 16#e1#, 16#c6#, 16#52#, 16#ff#, 16#2f#, 16#a7#, 16#79#,
               16#2a#, 16#08#, 16#de#, 16#f2#, 16#e4#, 16#e3#, 16#3c#, 16#4a#,
               others => 0));
      Ref_Sk_Ar     : constant Types.Key_Type
        := (Size => 64,
            Data =>
              (16#7f#, 16#28#, 16#be#, 16#b3#, 16#22#, 16#99#, 16#de#, 16#08#,
               16#4e#, 16#11#, 16#35#, 16#e6#, 16#57#, 16#9a#, 16#c7#, 16#c9#,
               16#a9#, 16#3a#, 16#7a#, 16#76#, 16#3b#, 16#cd#, 16#46#, 16#d1#,
               16#de#, 16#23#, 16#f8#, 16#83#, 16#45#, 16#f8#, 16#20#, 16#54#,
               16#51#, 16#9b#, 16#a1#, 16#be#, 16#7f#, 16#44#, 16#ca#, 16#6a#,
               16#7c#, 16#0a#, 16#cf#, 16#36#, 16#60#, 16#23#, 16#5f#, 16#ab#,
               16#49#, 16#1f#, 16#8d#, 16#11#, 16#ad#, 16#f5#, 16#19#, 16#09#,
               16#99#, 16#b4#, 16#6a#, 16#da#, 16#bf#, 16#f0#, 16#01#, 16#9b#,
               others => 0));
      Ref_Sk_Ei     : constant Types.Key_Type
        := (Size => 32,
            Data =>
              (16#4b#, 16#0f#, 16#95#, 16#aa#, 16#0a#, 16#8c#, 16#23#, 16#5e#,
               16#97#, 16#fa#, 16#c1#, 16#59#, 16#92#, 16#b3#, 16#bd#, 16#46#,
               16#6e#, 16#82#, 16#4c#, 16#ab#, 16#e6#, 16#2c#, 16#d8#, 16#4e#,
               16#c3#, 16#ee#, 16#cf#, 16#8d#, 16#b1#, 16#de#, 16#58#, 16#1c#,
               others => 0));
      Ref_Sk_Er     : constant Types.Key_Type
        := (Size => 32,
            Data =>
              (16#0a#, 16#cd#, 16#15#, 16#f1#, 16#76#, 16#5e#, 16#d9#, 16#36#,
               16#53#, 16#f7#, 16#db#, 16#ff#, 16#54#, 16#6c#, 16#d0#, 16#db#,
               16#09#, 16#18#, 16#65#, 16#01#, 16#df#, 16#24#, 16#b8#, 16#e5#,
               16#bf#, 16#88#, 16#1b#, 16#a0#, 16#d4#, 16#17#, 16#2f#, 16#21#,
               others => 0));
      Res           : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Contexts.dh.create
        (Id       => 1,
         dha_id   => Tkmrpc.Types.Dha_Id_Type (Constants.Modp_4096),
         secvalue => Types.Null_Dh_Priv_Type);
      Contexts.dh.generate (Id        => 1,
                            dh_key    => Shared_Secret,
                            timestamp => 0);
      Contexts.nc.create (Id    => 1,
                          nonce => Nonce_Loc);
      Contexts.isa.create (Id            => 2,
                           ae_id         => 1,
                           ia_id         => 1,
                           sk_d          => Parent_Sk_D,
                           creation_time => 0);
      declare
         use type Tkmrpc.Types.Key_Type;

         Sk_Ai, Sk_Ar, Sk_Ei, Sk_Er : Types.Key_Type;
      begin
         Servers.Ike.Isa_Create_Child
           (Result        => Res,
            Isa_Id        => 1,
            Parent_Isa_Id => 2,
            Ia_Id         => 1,
            Dh_Id         => 1,
            Nc_Loc_Id     => 1,
            Nonce_Rem     => Nonce_Rem,
            Initiator     => 1,
            Spi_Loc       => 15682998364295083393,
            Spi_Rem       => 11949823602698735948,
            Sk_Ai         => Sk_Ai,
            Sk_Ar         => Sk_Ar,
            Sk_Ei         => Sk_Ei,
            Sk_Er         => Sk_Er);

         Assert (Condition => Res = Results.Ok,
                 Message   => "Isa_Create_Child failed");

         Assert (Condition => Sk_Ai = Ref_Sk_Ai,
                 Message   => "Sk_Ai mismatch");
         Assert (Condition => Sk_Ar = Ref_Sk_Ar,
                 Message   => "Sk_Ar mismatch");
         Assert (Condition => Sk_Ei = Ref_Sk_Ei,
                 Message   => "Sk_Ei mismatch");
         Assert (Condition => Sk_Er = Ref_Sk_Er,
                 Message   => "Sk_Er mismatch");
      end;

      Assert (Condition => Contexts.isa.Has_sk_d
              (Id   => 1,
               sk_d => Ref_Sk_D),
              Message   => "Sk_D mismatch");
      Assert (Condition => Contexts.isa.Has_State
              (Id    => 1,
               State => Contexts.isa.active),
              Message   => "ISA context not 'active'");
      Assert (Condition => Contexts.nc.Has_State
              (Id    => 1,
               State => Contexts.nc.clean),
              Message   => "Nc context not 'clean'");
      Assert (Condition => Contexts.dh.Has_State
              (Id    => 1,
               State => Contexts.dh.clean),
              Message   => "Dh context state mismatch");

      Servers.Ike.Isa_Reset (Result => Res,
                             Isa_Id => 1);
      Assert (Condition => Res = Results.Ok,
              Message   => "Isa_Reset failed");
      Assert (Condition => Contexts.isa.Has_State
              (Id    => 1,
               State => Contexts.isa.clean),
              Message   => "ISA context not 'clean'");

      Servers.Ike.Isa_Reset (Result => Res,
                             Isa_Id => 2);
      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Isa_Reset (Result => Res,
                                Isa_Id => 1);
         Servers.Ike.Isa_Reset (Result => Res,
                                Isa_Id => 2);
         Servers.Ike.Nc_Reset (Result => Res,
                               Nc_Id  => 1);
         Servers.Ike.Dh_Reset (Result => Res,
                               Dh_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Isa_Create_Child;

   -------------------------------------------------------------------------

   procedure Check_Isa_Skip_Create_First
   is
      use type Tkmrpc.Results.Result_Type;
      use type Contexts.ae.ae_State_Type;

      Res : Results.Result_Type;
   begin
      Servers.Ike.Init;
      Contexts.dh.create
        (Id       => 1,
         dha_id   => Tkmrpc.Types.Dha_Id_Type (Constants.Modp_4096),
         secvalue => Types.Null_Dh_Priv_Type);
      Contexts.dh.generate (Id        => 1,
                            dh_key    => Types.Null_Dh_Key_Type,
                            timestamp => 0);
      Contexts.nc.create (Id    => 1,
                          nonce => Types.Null_Nonce_Type);
      Contexts.ae.create
        (Id              => 1,
         iag_id          => 1,
         dhag_id         => 1,
         creation_time   => 1,
         initiator       => 1,
         sk_ike_auth_loc => (Size => 64, Data => (others => 1)),
         sk_ike_auth_rem => (Size => 64, Data => (others => 1)),
         nonce_loc       => (Size => 64, Data => (others => 1)),
         nonce_rem       => (Size => 64, Data => (others => 1)));
      Contexts.ae.sign
        (Id    => 1,
         lc_id => 1);
      Contexts.ae.authenticate
        (Id              => 1,
         ca_context      => 1,
         ra_id           => 1,
         remote_identity => 1,
         not_before      => 1,
         not_after       => 1);
      Contexts.isa.create (Id            => 1,
                           ae_id         => 1,
                           ia_id         => 1,
                           sk_d          => Types.Null_Key_Type,
                           creation_time => 0);

      Servers.Ike.Isa_Skip_Create_First (Result => Res,
                                         Isa_Id => 1);

      Assert (Condition => Res = Results.Ok,
              Message   => "Isa_Skip_Create_First failed");
      Assert (Condition => Contexts.ae.Get_State
              (Id => 1) = Contexts.ae.active,
              Message   => "AE context not active");

      Servers.Ike.Isa_Reset (Result => Res,
                             Isa_Id => 1);
      Servers.Ike.Ae_Reset (Result => Res,
                            Ae_Id  => 1);
      Servers.Ike.Nc_Reset (Result => Res,
                            Nc_Id  => 1);
      Servers.Ike.Dh_Reset (Result => Res,
                            Dh_Id  => 1);
      Servers.Ike.Finalize;

   exception
      when others =>
         Servers.Ike.Isa_Reset (Result => Res,
                                Isa_Id => 1);
         Servers.Ike.Ae_Reset (Result => Res,
                               Ae_Id  => 1);
         Servers.Ike.Nc_Reset (Result => Res,
                               Nc_Id  => 1);
         Servers.Ike.Dh_Reset (Result => Res,
                               Dh_Id  => 1);
         Servers.Ike.Finalize;
         raise;
   end Check_Isa_Skip_Create_First;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "IKE server ISA tests");
      T.Add_Test_Routine
        (Routine => Check_Isa_Create'Access,
         Name    => "Check Isa_Create");
      T.Add_Test_Routine
        (Routine => Check_Isa_Create_Child'Access,
         Name    => "Check Isa_Create_Child");
      T.Add_Test_Routine
        (Routine => Check_Isa_Skip_Create_First'Access,
         Name    => "Check Isa_Skip_Create_First");
   end Initialize;

end Server_Ike_Isa_Tests;
