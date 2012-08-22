with GNAT.SHA512;

with Tkmrpc.Types;

with Tkm.Crypto.Hmac;

pragma Elaborate_All (Tkm.Crypto.Hmac);

package body Hmac_Tests is

   use Ahven;
   use Tkm;
   use type Tkmrpc.Types.Byte_Sequence;

   package Hmac_Sha512 is new Tkm.Crypto.Hmac
     (Hash_Block_Size => 128,
      Hash_Length     => 64,
      Hash_Ctx_Type   => GNAT.SHA512.Context,
      Initial_Ctx     => GNAT.SHA512.Initial_Context,
      Update          => GNAT.SHA512.Update,
      Digest          => GNAT.SHA512.Digest);

   -------------------------------------------------------------------------

   procedure Case1_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 20)
        := (others => 16#0b#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence
        := (16#48#, 16#69#, 16#20#, 16#54#, 16#68#, 16#65#, 16#72#,
            16#65#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#87#, 16#aa#, 16#7c#, 16#de#, 16#a5#, 16#ef#, 16#61#, 16#9d#,
            16#4f#, 16#f0#, 16#b4#, 16#24#, 16#1a#, 16#1d#, 16#6c#, 16#b0#,
            16#23#, 16#79#, 16#f4#, 16#e2#, 16#ce#, 16#4e#, 16#c2#, 16#78#,
            16#7a#, 16#d0#, 16#b3#, 16#05#, 16#45#, 16#e1#, 16#7c#, 16#de#,
            16#da#, 16#a8#, 16#33#, 16#b7#, 16#d6#, 16#b8#, 16#a7#, 16#02#,
            16#03#, 16#8b#, 16#27#, 16#4e#, 16#ae#, 16#a3#, 16#f4#, 16#e4#,
            16#be#, 16#9d#, 16#91#, 16#4e#, 16#eb#, 16#61#, 16#f1#, 16#70#,
            16#2e#, 16#69#, 16#6c#, 16#20#, 16#3a#, 16#12#, 16#68#, 16#54#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case1_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case2_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 4)
        := (16#4a#, 16#65#, 16#66#, 16#65#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence
        := (16#77#, 16#68#, 16#61#, 16#74#, 16#20#, 16#64#, 16#6f#, 16#20#,
            16#79#, 16#61#, 16#20#, 16#77#, 16#61#, 16#6e#, 16#74#, 16#20#,
            16#66#, 16#6f#, 16#72#, 16#20#, 16#6e#, 16#6f#, 16#74#, 16#68#,
            16#69#, 16#6e#, 16#67#, 16#3f#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#16#, 16#4b#, 16#7a#, 16#7b#, 16#fc#, 16#f8#, 16#19#, 16#e2#,
            16#e3#, 16#95#, 16#fb#, 16#e7#, 16#3b#, 16#56#, 16#e0#, 16#a3#,
            16#87#, 16#bd#, 16#64#, 16#22#, 16#2e#, 16#83#, 16#1f#, 16#d6#,
            16#10#, 16#27#, 16#0c#, 16#d7#, 16#ea#, 16#25#, 16#05#, 16#54#,
            16#97#, 16#58#, 16#bf#, 16#75#, 16#c0#, 16#5a#, 16#99#, 16#4a#,
            16#6d#, 16#03#, 16#4f#, 16#65#, 16#f8#, 16#f0#, 16#e6#, 16#fd#,
            16#ca#, 16#ea#, 16#b1#, 16#a3#, 16#4d#, 16#4a#, 16#6b#, 16#4b#,
            16#63#, 16#6e#, 16#07#, 16#0a#, 16#38#, 16#bc#, 16#e7#, 16#37#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case2_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case3_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 20)
        := (others => 16#aa#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence (1 .. 50)
        := (others => 16#dd#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#fa#, 16#73#, 16#b0#, 16#08#, 16#9d#, 16#56#, 16#a2#, 16#84#,
            16#ef#, 16#b0#, 16#f0#, 16#75#, 16#6c#, 16#89#, 16#0b#, 16#e9#,
            16#b1#, 16#b5#, 16#db#, 16#dd#, 16#8e#, 16#e8#, 16#1a#, 16#36#,
            16#55#, 16#f8#, 16#3e#, 16#33#, 16#b2#, 16#27#, 16#9d#, 16#39#,
            16#bf#, 16#3e#, 16#84#, 16#82#, 16#79#, 16#a7#, 16#22#, 16#c8#,
            16#06#, 16#b4#, 16#85#, 16#a4#, 16#7e#, 16#67#, 16#c8#, 16#07#,
            16#b9#, 16#46#, 16#a3#, 16#37#, 16#be#, 16#e8#, 16#94#, 16#26#,
            16#74#, 16#27#, 16#88#, 16#59#, 16#e1#, 16#32#, 16#92#, 16#fb#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case3_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case4_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence
        := (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#,
            16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#, 16#10#,
            16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#, 16#18#,
            16#19#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence (1 .. 50)
        := (others => 16#cd#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#b0#, 16#ba#, 16#46#, 16#56#, 16#37#, 16#45#, 16#8c#, 16#69#,
            16#90#, 16#e5#, 16#a8#, 16#c5#, 16#f6#, 16#1d#, 16#4a#, 16#f7#,
            16#e5#, 16#76#, 16#d9#, 16#7f#, 16#f9#, 16#4b#, 16#87#, 16#2d#,
            16#e7#, 16#6f#, 16#80#, 16#50#, 16#36#, 16#1e#, 16#e3#, 16#db#,
            16#a9#, 16#1c#, 16#a5#, 16#c1#, 16#1a#, 16#a2#, 16#5e#, 16#b4#,
            16#d6#, 16#79#, 16#27#, 16#5c#, 16#c5#, 16#78#, 16#80#, 16#63#,
            16#a5#, 16#f1#, 16#97#, 16#41#, 16#12#, 16#0c#, 16#4f#, 16#2d#,
            16#e2#, 16#ad#, 16#eb#, 16#eb#, 16#10#, 16#a2#, 16#98#, 16#dd#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case4_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case5_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 20)
        := (others => 16#0c#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence
        := (16#54#, 16#65#, 16#73#, 16#74#, 16#20#, 16#57#, 16#69#, 16#74#,
            16#68#, 16#20#, 16#54#, 16#72#, 16#75#, 16#6e#, 16#63#, 16#61#,
            16#74#, 16#69#, 16#6f#, 16#6e#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#41#, 16#5f#, 16#ad#, 16#62#, 16#71#, 16#58#, 16#0a#, 16#53#,
            16#1d#, 16#41#, 16#79#, 16#bc#, 16#89#, 16#1d#, 16#87#, 16#a6#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) (1 .. 16) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case5_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case6_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 131)
        := (others => 16#aa#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence
        := (16#54#, 16#65#, 16#73#, 16#74#, 16#20#, 16#55#, 16#73#, 16#69#,
            16#6e#, 16#67#, 16#20#, 16#4c#, 16#61#, 16#72#, 16#67#, 16#65#,
            16#72#, 16#20#, 16#54#, 16#68#, 16#61#, 16#6e#, 16#20#, 16#42#,
            16#6c#, 16#6f#, 16#63#, 16#6b#, 16#2d#, 16#53#, 16#69#, 16#7a#,
            16#65#, 16#20#, 16#4b#, 16#65#, 16#79#, 16#20#, 16#2d#, 16#20#,
            16#48#, 16#61#, 16#73#, 16#68#, 16#20#, 16#4b#, 16#65#, 16#79#,
            16#20#, 16#46#, 16#69#, 16#72#, 16#73#, 16#74#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#80#, 16#b2#, 16#42#, 16#63#, 16#c7#, 16#c1#, 16#a3#, 16#eb#,
            16#b7#, 16#14#, 16#93#, 16#c1#, 16#dd#, 16#7b#, 16#e8#, 16#b4#,
            16#9b#, 16#46#, 16#d1#, 16#f4#, 16#1b#, 16#4a#, 16#ee#, 16#c1#,
            16#12#, 16#1b#, 16#01#, 16#37#, 16#83#, 16#f8#, 16#f3#, 16#52#,
            16#6b#, 16#56#, 16#d0#, 16#37#, 16#e0#, 16#5f#, 16#25#, 16#98#,
            16#bd#, 16#0f#, 16#d2#, 16#21#, 16#5d#, 16#6a#, 16#1e#, 16#52#,
            16#95#, 16#e6#, 16#4f#, 16#73#, 16#f6#, 16#3f#, 16#0a#, 16#ec#,
            16#8b#, 16#91#, 16#5a#, 16#98#, 16#5d#, 16#78#, 16#65#, 16#98#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case6_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Case7_Hmac_Sha512
   is
      Mac_Ctx   : Hmac_Sha512.Context_Type;
      Ref_Key   : constant Tkmrpc.Types.Byte_Sequence (1 .. 131)
        := (others => 16#aa#);
      Ref_Data  : constant Tkmrpc.Types.Byte_Sequence
        := (16#54#, 16#68#, 16#69#, 16#73#, 16#20#, 16#69#, 16#73#, 16#20#,
            16#61#, 16#20#, 16#74#, 16#65#, 16#73#, 16#74#, 16#20#, 16#75#,
            16#73#, 16#69#, 16#6e#, 16#67#, 16#20#, 16#61#, 16#20#, 16#6c#,
            16#61#, 16#72#, 16#67#, 16#65#, 16#72#, 16#20#, 16#74#, 16#68#,
            16#61#, 16#6e#, 16#20#, 16#62#, 16#6c#, 16#6f#, 16#63#, 16#6b#,
            16#2d#, 16#73#, 16#69#, 16#7a#, 16#65#, 16#20#, 16#6b#, 16#65#,
            16#79#, 16#20#, 16#61#, 16#6e#, 16#64#, 16#20#, 16#61#, 16#20#,
            16#6c#, 16#61#, 16#72#, 16#67#, 16#65#, 16#72#, 16#20#, 16#74#,
            16#68#, 16#61#, 16#6e#, 16#20#, 16#62#, 16#6c#, 16#6f#, 16#63#,
            16#6b#, 16#2d#, 16#73#, 16#69#, 16#7a#, 16#65#, 16#20#, 16#64#,
            16#61#, 16#74#, 16#61#, 16#2e#, 16#20#, 16#54#, 16#68#, 16#65#,
            16#20#, 16#6b#, 16#65#, 16#79#, 16#20#, 16#6e#, 16#65#, 16#65#,
            16#64#, 16#73#, 16#20#, 16#74#, 16#6f#, 16#20#, 16#62#, 16#65#,
            16#20#, 16#68#, 16#61#, 16#73#, 16#68#, 16#65#, 16#64#, 16#20#,
            16#62#, 16#65#, 16#66#, 16#6f#, 16#72#, 16#65#, 16#20#, 16#62#,
            16#65#, 16#69#, 16#6e#, 16#67#, 16#20#, 16#75#, 16#73#, 16#65#,
            16#64#, 16#20#, 16#62#, 16#79#, 16#20#, 16#74#, 16#68#, 16#65#,
            16#20#, 16#48#, 16#4d#, 16#41#, 16#43#, 16#20#, 16#61#, 16#6c#,
            16#67#, 16#6f#, 16#72#, 16#69#, 16#74#, 16#68#, 16#6d#, 16#2e#);
      Ref_Value : constant Tkmrpc.Types.Byte_Sequence
        := (16#e3#, 16#7b#, 16#6a#, 16#77#, 16#5d#, 16#c8#, 16#7d#, 16#ba#,
            16#a4#, 16#df#, 16#a9#, 16#f9#, 16#6e#, 16#5e#, 16#3f#, 16#fd#,
            16#de#, 16#bd#, 16#71#, 16#f8#, 16#86#, 16#72#, 16#89#, 16#86#,
            16#5d#, 16#f5#, 16#a3#, 16#2d#, 16#20#, 16#cd#, 16#c9#, 16#44#,
            16#b6#, 16#02#, 16#2c#, 16#ac#, 16#3c#, 16#49#, 16#82#, 16#b1#,
            16#0d#, 16#5e#, 16#eb#, 16#55#, 16#c3#, 16#e4#, 16#de#, 16#15#,
            16#13#, 16#46#, 16#76#, 16#fb#, 16#6d#, 16#e0#, 16#44#, 16#60#,
            16#65#, 16#c9#, 16#74#, 16#40#, 16#fa#, 16#8c#, 16#6a#, 16#58#);
   begin
      Hmac_Sha512.Init (Ctx => Mac_Ctx,
                        Key => Ref_Key);
      Assert (Condition => Hmac_Sha512.Generate
              (Ctx  => Mac_Ctx,
               Data => Ref_Data) = Ref_Value,
              Message   => "Computed HMAC mismatch");
   end Case7_Hmac_Sha512;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "HMAC tests (HMAC-SHA-512-256)");
      T.Add_Test_Routine
        (Routine => Case1_Hmac_Sha512'Access,
         Name    => "Test Case 1");
      T.Add_Test_Routine
        (Routine => Case2_Hmac_Sha512'Access,
         Name    => "Test Case 2");
      T.Add_Test_Routine
        (Routine => Case3_Hmac_Sha512'Access,
         Name    => "Test Case 3");
      T.Add_Test_Routine
        (Routine => Case4_Hmac_Sha512'Access,
         Name    => "Test Case 4");
      T.Add_Test_Routine
        (Routine => Case5_Hmac_Sha512'Access,
         Name    => "Test Case 5");
      T.Add_Test_Routine
        (Routine => Case6_Hmac_Sha512'Access,
         Name    => "Test Case 6");
      T.Add_Test_Routine
        (Routine => Case7_Hmac_Sha512'Access,
         Name    => "Test Case 7");
   end Initialize;

end Hmac_Tests;
