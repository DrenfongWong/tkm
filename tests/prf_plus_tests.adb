with Tkmrpc.Types;

with Tkm.Crypto.Hmac_Sha512;
with Tkm.Crypto.Prf_Plus;

pragma Elaborate_All (Tkm.Crypto.Prf_Plus);

package body Prf_Plus_Tests is

   use Ahven;
   use Tkm;

   package Prf_Plus_Hmac_Sha512 is new Tkm.Crypto.Prf_Plus
     (Prf_Length   => Crypto.Hmac_Sha512.Hash_Output_Length,
      Prf_Ctx_Type => Crypto.Hmac_Sha512.Context_Type,
      Init         => Crypto.Hmac_Sha512.Init,
      Generate     => Crypto.Hmac_Sha512.Generate);

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "PRF+ tests");
      T.Add_Test_Routine
        (Routine => Verify_Prf_Plus_Hmac_Sha512'Access,
         Name    => "PRF+-HMAC-SHA512");
      T.Add_Test_Routine
        (Routine => Seed_Exceeds_Max'Access,
         Name    => "Invalid seed size");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Seed_Exceeds_Max
   is
      Context : Prf_Plus_Hmac_Sha512.Context_Type;
      Seed    : constant Tkmrpc.Types.Byte_Sequence (1 .. 1024)
        := (others => 12);
   begin
      Prf_Plus_Hmac_Sha512.Init (Ctx  => Context,
                                 Key  => (12, 12),
                                 Seed => Seed);
      Fail (Message => "Exception expected");

   exception
      when Prf_Plus_Hmac_Sha512.Prf_Plus_Error => null;
   end Seed_Exceeds_Max;

   -------------------------------------------------------------------------

   procedure Verify_Prf_Plus_Hmac_Sha512
   is
      use type Tkmrpc.Types.Byte_Sequence;

      Context : Prf_Plus_Hmac_Sha512.Context_Type;
      Key     : constant Tkmrpc.Types.Byte_Sequence
        := (16#9f#, 16#17#, 16#eb#, 16#85#, 16#cb#, 16#58#, 16#2b#, 16#55#,
            16#51#, 16#05#, 16#7e#, 16#c4#, 16#a0#, 16#13#, 16#be#, 16#4a#,
            16#a9#, 16#77#, 16#64#, 16#f5#, 16#36#, 16#75#, 16#97#, 16#e5#,
            16#92#, 16#94#, 16#55#, 16#9a#, 16#9e#, 16#cd#, 16#a1#, 16#74#,
            16#10#, 16#33#, 16#47#, 16#95#, 16#35#, 16#97#, 16#39#, 16#cb#,
            16#21#, 16#4a#, 16#aa#, 16#fe#, 16#82#, 16#89#, 16#32#, 16#78#,
            16#90#, 16#bb#, 16#d7#, 16#5e#, 16#16#, 16#2e#, 16#c4#, 16#01#,
            16#9d#, 16#d2#, 16#db#, 16#9d#, 16#75#, 16#17#, 16#da#, 16#f2#);
      Seed    : constant Tkmrpc.Types.Byte_Sequence
        := (16#97#, 16#e5#, 16#88#, 16#65#, 16#d7#, 16#24#, 16#f7#, 16#ed#,
            16#9d#, 16#90#, 16#c9#, 16#f7#, 16#94#, 16#52#, 16#f0#, 16#dc#,
            16#53#, 16#23#, 16#48#, 16#16#, 16#35#, 16#39#, 16#b1#, 16#2a#,
            16#37#, 16#69#, 16#22#, 16#8d#, 16#9d#, 16#f5#, 16#bf#, 16#8f#,
            16#76#, 16#7e#, 16#fb#, 16#68#, 16#84#, 16#4d#, 16#53#, 16#56#,
            16#b2#, 16#55#, 16#7d#, 16#fd#, 16#e7#, 16#45#, 16#67#, 16#ef#,
            16#00#, 16#a1#, 16#1a#, 16#90#, 16#4d#, 16#e3#, 16#50#, 16#48#,
            16#49#, 16#c2#, 16#87#, 16#11#, 16#3d#, 16#e7#, 16#6d#, 16#84#,
            16#14#, 16#1f#, 16#80#, 16#5b#, 16#d0#, 16#77#, 16#17#, 16#77#,
            16#b9#, 16#98#, 16#f3#, 16#e8#, 16#f1#, 16#aa#, 16#32#, 16#3f#);
      First   : constant Tkmrpc.Types.Byte_Sequence
        := (16#2d#, 16#20#, 16#82#, 16#1e#, 16#01#, 16#b2#, 16#93#, 16#c3#,
            16#45#, 16#1e#, 16#b5#, 16#97#, 16#54#, 16#8a#, 16#03#, 16#d7#,
            16#ae#, 16#6c#, 16#2b#, 16#80#, 16#08#, 16#b3#, 16#fc#, 16#5c#,
            16#f3#, 16#ad#, 16#c4#, 16#66#, 16#a0#, 16#f2#, 16#6b#, 16#59#,
            16#b6#, 16#2d#, 16#bd#, 16#9d#, 16#ba#, 16#fe#, 16#21#, 16#87#,
            16#50#, 16#05#, 16#8e#, 16#35#, 16#b5#, 16#9a#, 16#02#, 16#ec#,
            16#6a#, 16#a0#, 16#26#, 16#47#, 16#79#, 16#78#, 16#f7#, 16#3d#,
            16#c7#, 16#21#, 16#e0#, 16#38#, 16#8d#, 16#a0#, 16#e8#, 16#e1#);
      Second  : constant Tkmrpc.Types.Byte_Sequence
        := (16#ec#, 16#f6#, 16#58#, 16#04#, 16#e4#, 16#9d#, 16#36#, 16#7d#,
            16#79#, 16#03#, 16#b4#, 16#d3#, 16#21#, 16#10#, 16#0f#, 16#f7#,
            16#55#, 16#2d#, 16#46#, 16#4b#, 16#a6#, 16#fc#, 16#03#, 16#2a#,
            16#18#, 16#a2#, 16#fc#, 16#50#, 16#7a#, 16#b2#, 16#76#, 16#43#,
            16#4f#, 16#ba#, 16#11#, 16#ba#, 16#c7#, 16#ec#, 16#7b#, 16#81#,
            16#a4#, 16#3e#, 16#fa#, 16#d8#, 16#d4#, 16#6a#, 16#10#, 16#9f#,
            16#fc#, 16#7b#, 16#3d#, 16#ce#, 16#a9#, 16#d3#, 16#5c#, 16#4e#,
            16#2a#, 16#ff#, 16#7a#, 16#d7#, 16#35#, 16#75#, 16#6e#, 16#08#);
      Third   : constant Tkmrpc.Types.Byte_Sequence
        := (16#1a#, 16#53#, 16#2f#, 16#de#, 16#0f#, 16#f9#, 16#e2#, 16#9c#,
            16#77#, 16#3b#, 16#37#, 16#45#, 16#b5#, 16#09#, 16#78#, 16#4d#,
            16#cf#, 16#41#, 16#8a#, 16#92#, 16#57#, 16#d5#, 16#58#, 16#01#,
            16#c2#, 16#2c#, 16#7c#, 16#d2#, 16#c8#, 16#b3#, 16#fb#, 16#73#);
      Fourth  : constant Tkmrpc.Types.Byte_Sequence
        := (16#60#, 16#9f#, 16#8c#, 16#34#, 16#62#, 16#fe#, 16#b5#, 16#5b#,
            16#25#, 16#2e#, 16#0d#, 16#29#, 16#10#, 16#b6#, 16#08#, 16#59#,
            16#a6#, 16#f4#, 16#90#, 16#75#, 16#31#, 16#84#, 16#2e#, 16#b3#,
            16#19#, 16#9c#, 16#34#, 16#af#, 16#a4#, 16#72#, 16#71#, 16#ce#,
            16#c8#, 16#15#, 16#33#, 16#92#, 16#2e#, 16#66#, 16#49#, 16#69#,
            16#94#, 16#16#, 16#5d#, 16#d5#, 16#df#, 16#78#, 16#d1#, 16#4c#,
            16#9c#, 16#40#, 16#d0#, 16#53#, 16#9b#, 16#ad#, 16#ad#, 16#40#,
            16#62#, 16#96#, 16#71#, 16#12#, 16#35#, 16#38#, 16#f0#, 16#c0#,
            16#5e#, 16#3e#, 16#d6#, 16#f6#, 16#78#, 16#de#, 16#9f#, 16#10#,
            16#62#, 16#c6#, 16#5d#, 16#cf#, 16#0c#, 16#10#, 16#70#, 16#15#,
            16#3a#, 16#45#, 16#c3#, 16#41#, 16#99#, 16#c0#, 16#73#, 16#0f#,
            16#48#, 16#7e#, 16#c3#, 16#5a#, 16#6f#, 16#91#, 16#1c#, 16#b6#,
            16#df#, 16#94#, 16#ec#, 16#b0#, 16#0b#, 16#27#, 16#38#, 16#72#,
            16#fb#, 16#e1#, 16#53#, 16#2c#, 16#67#, 16#a4#, 16#8e#, 16#9b#,
            16#ac#, 16#d8#, 16#22#, 16#8c#, 16#20#, 16#77#, 16#8b#, 16#a8#,
            16#f6#, 16#24#, 16#7f#, 16#d7#, 16#04#, 16#4f#, 16#58#, 16#c1#);
   begin
      Prf_Plus_Hmac_Sha512.Init (Ctx  => Context,
                                 Key  => Key,
                                 Seed => Seed);

      Assert (Condition => Prf_Plus_Hmac_Sha512.Generate
              (Ctx    => Context,
               Length => 64) = First,
              Message   => "Output mismatch (first)");
      Assert (Condition => Prf_Plus_Hmac_Sha512.Generate
              (Ctx    => Context,
               Length => 64) = Second,
              Message   => "Output mismatch (second)");
      Assert (Condition => Prf_Plus_Hmac_Sha512.Generate
              (Ctx    => Context,
               Length => 32) = Third,
              Message   => "Output mismatch (third)");
      Assert (Condition => Prf_Plus_Hmac_Sha512.Generate
              (Ctx    => Context,
               Length => 128) = Fourth,
              Message   => "Output mismatch (fourth)");
   end Verify_Prf_Plus_Hmac_Sha512;

end Prf_Plus_Tests;
