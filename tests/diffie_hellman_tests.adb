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

with Tkm.Utils;
with Tkm.Diffie_Hellman;

package body Diffie_Hellman_Tests is

   use Ahven;
   use Tkm;

   Random_Chunk : constant Tkmrpc.Types.Byte_Sequence :=
     (16#59#, 16#c2#, 16#a4#, 16#72#, 16#fc#, 16#ed#, 16#b9#, 16#82#, 16#ac#,
      16#70#, 16#1f#, 16#3c#, 16#cd#, 16#75#, 16#67#, 16#07#, 16#89#, 16#70#,
      16#9f#, 16#18#, 16#9c#, 16#cb#, 16#85#, 16#f6#, 16#ad#, 16#90#, 16#fd#,
      16#5e#, 16#eb#, 16#8e#, 16#bc#, 16#c2#, 16#a0#, 16#fb#, 16#0f#, 16#0e#,
      16#97#, 16#a6#, 16#4a#, 16#8f#, 16#af#, 16#82#, 16#88#, 16#ad#, 16#30#,
      16#02#, 16#e7#, 16#aa#, 16#54#, 16#7e#, 16#a3#, 16#b4#, 16#81#, 16#5d#,
      16#52#, 16#41#, 16#06#, 16#be#, 16#6a#, 16#65#, 16#0a#, 16#9c#, 16#56#,
      16#b4#, 16#1e#, 16#1f#, 16#b2#, 16#2e#, 16#f3#, 16#c9#, 16#71#, 16#79#,
      16#8d#, 16#b8#, 16#41#, 16#17#, 16#7c#, 16#fd#, 16#e9#, 16#64#, 16#38#,
      16#8e#, 16#52#, 16#bf#, 16#a7#, 16#47#, 16#9a#, 16#b7#, 16#59#, 16#21#,
      16#1b#, 16#95#, 16#32#, 16#13#, 16#92#, 16#72#, 16#e5#, 16#32#, 16#fb#,
      16#1d#, 16#1a#, 16#5a#, 16#ab#, 16#a0#, 16#03#, 16#54#, 16#2b#, 16#6e#,
      16#85#, 16#94#, 16#c8#, 16#8a#, 16#f4#, 16#40#, 16#1c#, 16#40#, 16#9e#,
      16#23#, 16#63#, 16#a0#, 16#eb#, 16#92#, 16#2e#, 16#c1#, 16#9e#, 16#ff#,
      16#d8#, 16#65#, 16#83#, 16#58#, 16#42#, 16#08#, 16#de#, 16#a0#, 16#53#,
      16#e5#, 16#7f#, 16#1e#, 16#6f#, 16#df#, 16#8b#, 16#13#, 16#7d#, 16#77#,
      16#d1#, 16#f0#, 16#17#, 16#76#, 16#ef#, 16#0a#, 16#e8#, 16#19#, 16#64#,
      16#57#, 16#b5#, 16#cc#, 16#44#, 16#2e#, 16#b6#, 16#a2#, 16#f2#, 16#e4#,
      16#d8#, 16#14#, 16#07#, 16#a1#, 16#d5#, 16#d4#, 16#c0#, 16#c3#, 16#cf#,
      16#0b#, 16#2f#, 16#db#, 16#d5#, 16#a9#, 16#59#, 16#c3#, 16#dc#, 16#90#,
      16#54#, 16#cb#, 16#76#, 16#50#, 16#cd#, 16#ba#, 16#15#, 16#03#, 16#98#,
      16#7a#, 16#b1#, 16#2c#, 16#1b#, 16#ca#, 16#4e#, 16#9e#, 16#bc#, 16#09#,
      16#e7#, 16#e7#, 16#48#, 16#01#, 16#c3#, 16#e5#, 16#e0#, 16#df#, 16#ae#,
      16#77#, 16#18#, 16#f6#, 16#51#, 16#e4#, 16#5c#, 16#d1#, 16#07#, 16#3e#,
      16#38#, 16#35#, 16#a8#, 16#75#, 16#56#, 16#f4#, 16#bc#, 16#5b#, 16#4b#,
      16#f0#, 16#14#, 16#6d#, 16#40#, 16#62#, 16#3d#, 16#e5#, 16#82#, 16#b7#,
      16#0d#, 16#a9#, 16#b2#, 16#17#, 16#0e#, 16#06#, 16#3f#, 16#10#, 16#78#,
      16#ae#, 16#77#, 16#93#, 16#4d#, 16#ef#, 16#d3#, 16#dc#, 16#ac#, 16#5a#,
      16#9b#, 16#bc#, 16#3b#, 16#3a#, 16#48#, 16#cd#, 16#53#, 16#22#, 16#95#,
      16#c3#, 16#0d#, 16#82#, 16#b6#, 16#1e#, 16#3a#, 16#12#, 16#e4#, 16#ba#,
      16#9e#, 16#49#, 16#67#, 16#49#, 16#75#, 16#59#, 16#4a#, 16#93#, 16#3e#,
      16#bc#, 16#8b#, 16#a1#, 16#3a#, 16#e3#, 16#04#, 16#7d#, 16#c3#, 16#61#,
      16#ef#, 16#6c#, 16#da#, 16#b5#, 16#42#, 16#5a#, 16#c2#, 16#b0#, 16#f2#,
      16#92#, 16#66#, 16#5d#, 16#e3#, 16#f7#, 16#b3#, 16#cb#, 16#71#, 16#3d#,
      16#84#, 16#3b#, 16#8e#, 16#69#, 16#7b#, 16#b7#, 16#95#, 16#7f#, 16#21#,
      16#0f#, 16#28#, 16#cc#, 16#b7#, 16#15#, 16#f8#, 16#ad#, 16#67#, 16#6c#,
      16#3d#, 16#a6#, 16#e9#, 16#8f#, 16#0e#, 16#90#, 16#48#, 16#4b#, 16#1c#,
      16#ca#, 16#5a#, 16#26#, 16#43#, 16#17#, 16#8f#, 16#fa#, 16#34#, 16#88#,
      16#34#, 16#ff#, 16#0c#, 16#15#, 16#29#, 16#7b#, 16#94#, 16#cf#, 16#d3#,
      16#21#, 16#4e#, 16#cf#, 16#e2#, 16#63#, 16#0b#, 16#32#, 16#c0#, 16#54#,
      16#e4#, 16#7e#, 16#31#, 16#ab#, 16#73#, 16#6b#, 16#5c#, 16#b3#, 16#9a#,
      16#c2#, 16#6a#, 16#ba#, 16#21#, 16#0c#, 16#a1#, 16#8e#, 16#89#, 16#c7#,
      16#f9#, 16#88#, 16#33#, 16#69#, 16#3e#, 16#38#, 16#4e#, 16#53#, 16#4c#,
      16#f1#, 16#05#, 16#fd#, 16#70#, 16#a0#, 16#c3#, 16#86#, 16#84#, 16#a3#,
      16#df#, 16#9e#, 16#2d#, 16#04#, 16#9e#, 16#01#, 16#a2#, 16#8c#, 16#97#,
      16#4a#, 16#19#, 16#2b#, 16#93#, 16#88#, 16#b7#, 16#9b#, 16#71#, 16#75#,
      16#4b#, 16#1e#, 16#b4#, 16#e2#, 16#6c#, 16#a5#, 16#03#, 16#a8#, 16#23#,
      16#b5#, 16#9d#, 16#7e#, 16#b5#, 16#58#, 16#9a#, 16#d4#, 16#2a#, 16#a9#,
      16#90#, 16#a5#, 16#72#, 16#15#, 16#97#, 16#98#, 16#d3#, 16#19#, 16#8d#,
      16#23#, 16#92#, 16#23#, 16#e2#, 16#54#, 16#f8#, 16#84#, 16#48#, 16#56#,
      16#fc#, 16#92#, 16#ac#, 16#75#, 16#8a#, 16#8f#, 16#5c#, 16#6e#, 16#a0#,
      16#5d#, 16#49#, 16#ba#, 16#02#, 16#57#, 16#17#, 16#6b#, 16#29#, 16#56#,
      16#82#, 16#82#, 16#1b#, 16#0b#, 16#ca#, 16#03#, 16#74#, 16#3d#, 16#a5#,
      16#e8#, 16#c5#, 16#a5#, 16#b3#, 16#71#, 16#39#, 16#0a#, 16#2e#, 16#c1#,
      16#e4#, 16#bc#, 16#f5#, 16#06#, 16#2d#, 16#15#, 16#e4#, 16#5c#, 16#f0#,
      16#a0#, 16#2f#, 16#f6#, 16#c7#, 16#09#, 16#e9#, 16#9d#, 16#5f#, 16#1a#,
      16#30#, 16#91#, 16#55#, 16#38#, 16#6a#, 16#0e#, 16#83#, 16#85#);
   --  512 bytes random data.

   Random_3072_Chunk : constant Tkmrpc.Types.Byte_Sequence :=
     (16#7a#, 16#e8#, 16#9b#, 16#d5#, 16#3b#, 16#3c#, 16#67#, 16#c8#, 16#2d#,
      16#fb#, 16#14#, 16#d8#, 16#be#, 16#5a#, 16#b3#, 16#6a#, 16#a3#, 16#66#,
      16#84#, 16#52#, 16#48#, 16#50#, 16#91#, 16#a3#, 16#15#, 16#91#, 16#63#,
      16#ae#, 16#13#, 16#cf#, 16#f7#, 16#82#, 16#7d#, 16#f4#, 16#9e#, 16#8f#,
      16#8e#, 16#b3#, 16#88#, 16#34#, 16#8f#, 16#5e#, 16#21#, 16#ff#, 16#ca#,
      16#3e#, 16#0d#, 16#00#, 16#aa#, 16#d2#, 16#86#, 16#b1#, 16#3c#, 16#08#,
      16#79#, 16#68#, 16#fe#, 16#9d#, 16#e0#, 16#ed#, 16#8d#, 16#0b#, 16#a5#,
      16#e1#, 16#a1#, 16#46#, 16#af#, 16#b9#, 16#51#, 16#76#, 16#dc#, 16#31#,
      16#da#, 16#33#, 16#1d#, 16#c1#, 16#45#, 16#ac#, 16#9e#, 16#62#, 16#2c#,
      16#99#, 16#f0#, 16#23#, 16#26#, 16#8b#, 16#d9#, 16#1b#, 16#5e#, 16#95#,
      16#de#, 16#38#, 16#1b#, 16#8c#, 16#96#, 16#aa#, 16#45#, 16#83#, 16#3c#,
      16#e9#, 16#40#, 16#3e#, 16#77#, 16#0d#, 16#82#, 16#c9#, 16#d7#, 16#b5#,
      16#d9#, 16#c7#, 16#2d#, 16#29#, 16#e7#, 16#9d#, 16#4c#, 16#13#, 16#74#,
      16#0f#, 16#38#, 16#74#, 16#fc#, 16#db#, 16#7c#, 16#9a#, 16#94#, 16#7f#,
      16#ff#, 16#c3#, 16#cf#, 16#1b#, 16#3f#, 16#e7#, 16#4e#, 16#95#, 16#22#,
      16#5b#, 16#f1#, 16#a4#, 16#b3#, 16#86#, 16#e5#, 16#8e#, 16#97#, 16#7e#,
      16#0b#, 16#f7#, 16#47#, 16#3a#, 16#5d#, 16#3a#, 16#7d#, 16#0b#, 16#10#,
      16#0f#, 16#99#, 16#a0#, 16#f7#, 16#d0#, 16#87#, 16#df#, 16#df#, 16#65#,
      16#58#, 16#79#, 16#3b#, 16#a0#, 16#32#, 16#b1#, 16#b6#, 16#ff#, 16#f6#,
      16#1e#, 16#0d#, 16#34#, 16#2d#, 16#c6#, 16#81#, 16#db#, 16#d4#, 16#7a#,
      16#87#, 16#15#, 16#f0#, 16#14#, 16#ba#, 16#bc#, 16#47#, 16#79#, 16#70#,
      16#ae#, 16#25#, 16#3e#, 16#f2#, 16#52#, 16#24#, 16#2b#, 16#7b#, 16#ec#,
      16#e3#, 16#db#, 16#d5#, 16#97#, 16#e3#, 16#cd#, 16#d9#, 16#d6#, 16#32#,
      16#65#, 16#97#, 16#9b#, 16#85#, 16#a6#, 16#a6#, 16#9f#, 16#5e#, 16#ce#,
      16#c8#, 16#78#, 16#a3#, 16#25#, 16#af#, 16#4e#, 16#71#, 16#50#, 16#a8#,
      16#ea#, 16#54#, 16#49#, 16#37#, 16#3d#, 16#7b#, 16#8e#, 16#d6#, 16#2b#,
      16#e2#, 16#a4#, 16#8f#, 16#ae#, 16#94#, 16#de#, 16#9d#, 16#4b#, 16#2c#,
      16#ce#, 16#85#, 16#d9#, 16#56#, 16#a1#, 16#25#, 16#5d#, 16#a9#, 16#3e#,
      16#87#, 16#80#, 16#fa#, 16#60#, 16#df#, 16#f1#, 16#27#, 16#88#, 16#01#,
      16#b3#, 16#ea#, 16#15#, 16#44#, 16#3f#, 16#99#, 16#6b#, 16#1b#, 16#45#,
      16#b7#, 16#7d#, 16#6a#, 16#69#, 16#ab#, 16#d7#, 16#bb#, 16#de#, 16#f1#,
      16#b5#, 16#bd#, 16#6a#, 16#89#, 16#9a#, 16#e6#, 16#a9#, 16#df#, 16#77#,
      16#14#, 16#88#, 16#5a#, 16#45#, 16#6d#, 16#cb#, 16#48#, 16#60#, 16#24#,
      16#00#, 16#26#, 16#88#, 16#67#, 16#b1#, 16#24#, 16#fb#, 16#23#, 16#54#,
      16#e2#, 16#f5#, 16#cb#, 16#02#, 16#21#, 16#76#, 16#66#, 16#cb#, 16#6f#,
      16#2f#, 16#9f#, 16#ac#, 16#e4#, 16#98#, 16#81#, 16#13#, 16#cf#, 16#53#,
      16#e4#, 16#ee#, 16#ae#, 16#8b#, 16#d1#, 16#c0#, 16#ea#, 16#b9#, 16#38#,
      16#16#, 16#d1#, 16#9e#, 16#31#, 16#7c#, 16#dd#, 16#9d#, 16#e4#, 16#72#,
      16#a1#, 16#66#, 16#04#, 16#7d#, 16#a9#, 16#64#, 16#34#, 16#70#, 16#02#,
      16#77#, 16#7d#, 16#01#, 16#71#, 16#59#, 16#50#, 16#6f#, 16#e7#, 16#30#,
      16#4a#, 16#1a#, 16#43#, 16#d8#, 16#08#, 16#69#, 16#d6#, 16#b8#, 16#29#,
      16#ed#, 16#db#, 16#2a#, 16#12#, 16#f3#, 16#ec#, 16#3b#, 16#b2#, 16#4a#,
      16#2e#, 16#50#, 16#bc#, 16#aa#, 16#20#, 16#97#);
   --  384 bytes random data (MODP-3072).

   Yb_Chunk : constant Tkmrpc.Types.Byte_Sequence :=
     (16#54#, 16#58#, 16#2c#, 16#a4#, 16#5e#, 16#5a#, 16#8b#, 16#e4#, 16#6e#,
      16#ff#, 16#fe#, 16#1f#, 16#51#, 16#d4#, 16#21#, 16#75#, 16#04#, 16#bd#,
      16#4c#, 16#74#, 16#59#, 16#d5#, 16#68#, 16#ac#, 16#9d#, 16#5a#, 16#a9#,
      16#05#, 16#ac#, 16#e0#, 16#08#, 16#3a#, 16#20#, 16#f7#, 16#40#, 16#79#,
      16#a1#, 16#9d#, 16#d0#, 16#23#, 16#61#, 16#63#, 16#5f#, 16#34#, 16#44#,
      16#50#, 16#00#, 16#c3#, 16#27#, 16#19#, 16#87#, 16#21#, 16#0f#, 16#5e#,
      16#e0#, 16#2a#, 16#7e#, 16#ab#, 16#7b#, 16#66#, 16#07#, 16#70#, 16#01#,
      16#a4#, 16#f0#, 16#3c#, 16#1f#, 16#a9#, 16#10#, 16#74#, 16#86#, 16#bc#,
      16#c5#, 16#a8#, 16#6c#, 16#22#, 16#ff#, 16#ea#, 16#5b#, 16#cc#, 16#24#,
      16#4e#, 16#c2#, 16#8a#, 16#fc#, 16#c7#, 16#6d#, 16#85#, 16#e8#, 16#b5#,
      16#bf#, 16#28#, 16#cb#, 16#0d#, 16#39#, 16#9d#, 16#5b#, 16#0b#, 16#c7#,
      16#34#, 16#3d#, 16#7c#, 16#9b#, 16#08#, 16#6b#, 16#36#, 16#06#, 16#ac#,
      16#73#, 16#21#, 16#87#, 16#76#, 16#e2#, 16#59#, 16#96#, 16#90#, 16#ad#,
      16#32#, 16#16#, 16#8d#, 16#59#, 16#7c#, 16#2b#, 16#78#, 16#15#, 16#fe#,
      16#a2#, 16#01#, 16#e7#, 16#9f#, 16#58#, 16#29#, 16#58#, 16#25#, 16#df#,
      16#bc#, 16#d6#, 16#66#, 16#c1#, 16#32#, 16#b6#, 16#87#, 16#70#, 16#e6#,
      16#77#, 16#3d#, 16#38#, 16#19#, 16#09#, 16#24#, 16#b3#, 16#01#, 16#ca#,
      16#90#, 16#fb#, 16#18#, 16#2c#, 16#28#, 16#50#, 16#af#, 16#b6#, 16#d6#,
      16#43#, 16#dc#, 16#ed#, 16#7e#, 16#c7#, 16#b2#, 16#b2#, 16#28#, 16#5e#,
      16#fe#, 16#32#, 16#52#, 16#d7#, 16#37#, 16#91#, 16#6f#, 16#b3#, 16#9e#,
      16#2b#, 16#9b#, 16#18#, 16#2b#, 16#94#, 16#1c#, 16#eb#, 16#fe#, 16#dc#,
      16#39#, 16#89#, 16#e9#, 16#20#, 16#16#, 16#5f#, 16#f8#, 16#ae#, 16#fc#,
      16#4f#, 16#8b#, 16#39#, 16#08#, 16#df#, 16#bb#, 16#58#, 16#6c#, 16#b4#,
      16#95#, 16#73#, 16#e8#, 16#cf#, 16#f3#, 16#ad#, 16#be#, 16#b2#, 16#39#,
      16#11#, 16#59#, 16#91#, 16#a9#, 16#86#, 16#64#, 16#71#, 16#84#, 16#fa#,
      16#06#, 16#ac#, 16#4a#, 16#55#, 16#31#, 16#b5#, 16#46#, 16#cd#, 16#8f#,
      16#e2#, 16#36#, 16#e9#, 16#0b#, 16#d1#, 16#06#, 16#31#, 16#b7#, 16#29#,
      16#0e#, 16#6a#, 16#36#, 16#4d#, 16#5c#, 16#d6#, 16#71#, 16#f9#, 16#2e#,
      16#c8#, 16#99#, 16#2f#, 16#65#, 16#08#, 16#8f#, 16#2a#, 16#b9#, 16#a9#,
      16#1e#, 16#ce#, 16#87#, 16#e4#, 16#69#, 16#21#, 16#da#, 16#b9#, 16#77#,
      16#d9#, 16#17#, 16#5a#, 16#5e#, 16#3f#, 16#5f#, 16#d4#, 16#c2#, 16#6e#,
      16#6b#, 16#5e#, 16#97#, 16#3c#, 16#2c#, 16#e1#, 16#f0#, 16#33#, 16#b5#,
      16#b1#, 16#29#, 16#5b#, 16#d7#, 16#d4#, 16#c8#, 16#f7#, 16#e0#, 16#d2#,
      16#6e#, 16#9c#, 16#aa#, 16#9c#, 16#62#, 16#69#, 16#ec#, 16#57#, 16#fd#,
      16#dd#, 16#70#, 16#da#, 16#ba#, 16#0e#, 16#94#, 16#ff#, 16#ae#, 16#29#,
      16#59#, 16#c5#, 16#6e#, 16#5a#, 16#d7#, 16#ac#, 16#d3#, 16#90#, 16#9d#,
      16#24#, 16#15#, 16#a8#, 16#1c#, 16#c9#, 16#89#, 16#f6#, 16#e4#, 16#61#,
      16#c1#, 16#10#, 16#02#, 16#93#, 16#80#, 16#5a#, 16#2f#, 16#1f#, 16#8b#,
      16#05#, 16#04#, 16#3e#, 16#d9#, 16#a7#, 16#8e#, 16#7b#, 16#a2#, 16#5f#,
      16#63#, 16#01#, 16#dc#, 16#b4#, 16#08#, 16#cd#, 16#3a#, 16#ea#, 16#59#,
      16#86#, 16#fd#, 16#e8#, 16#74#, 16#88#, 16#a4#, 16#af#, 16#b3#, 16#48#,
      16#cf#, 16#ec#, 16#01#, 16#9d#, 16#fb#, 16#e6#, 16#31#, 16#89#, 16#9c#,
      16#d2#, 16#cc#, 16#b7#, 16#0d#, 16#ca#, 16#29#, 16#f0#, 16#b3#, 16#6e#,
      16#f9#, 16#61#, 16#c2#, 16#fb#, 16#eb#, 16#23#, 16#50#, 16#c7#, 16#92#,
      16#52#, 16#a2#, 16#4c#, 16#81#, 16#d2#, 16#e1#, 16#d4#, 16#0e#, 16#3c#,
      16#01#, 16#62#, 16#b3#, 16#b2#, 16#ff#, 16#cd#, 16#2b#, 16#1b#, 16#22#,
      16#33#, 16#7d#, 16#48#, 16#c8#, 16#7f#, 16#2d#, 16#6c#, 16#ec#, 16#b3#,
      16#45#, 16#f0#, 16#97#, 16#62#, 16#7d#, 16#3e#, 16#cc#, 16#22#, 16#88#,
      16#d9#, 16#7d#, 16#3f#, 16#8b#, 16#9e#, 16#b2#, 16#51#, 16#48#, 16#e1#,
      16#20#, 16#2e#, 16#b5#, 16#d9#, 16#11#, 16#e4#, 16#05#, 16#ee#, 16#bd#,
      16#19#, 16#79#, 16#6f#, 16#f1#, 16#9f#, 16#8e#, 16#b0#, 16#b8#, 16#b4#,
      16#f8#, 16#22#, 16#33#, 16#bb#, 16#dd#, 16#7f#, 16#d7#, 16#48#, 16#20#,
      16#97#, 16#57#, 16#a1#, 16#b4#, 16#69#, 16#52#, 16#d1#, 16#33#, 16#e9#,
      16#b3#, 16#1e#, 16#26#, 16#14#, 16#5d#, 16#20#, 16#44#, 16#bb#, 16#5c#,
      16#1c#, 16#84#, 16#3c#, 16#57#, 16#a3#, 16#3a#, 16#00#, 16#45#, 16#ad#,
      16#b4#, 16#47#, 16#76#, 16#9b#, 16#d1#, 16#9b#, 16#6b#, 16#51#, 16#b8#,
      16#44#, 16#9a#, 16#25#, 16#7d#, 16#0e#, 16#5c#, 16#cc#, 16#05#);
   --  Other pubvalue.

   Yb_3072_Chunk : constant Tkmrpc.Types.Byte_Sequence :=
     (16#20#, 16#e8#, 16#aa#, 16#76#, 16#76#, 16#f5#, 16#e4#, 16#73#, 16#28#,
      16#08#, 16#03#, 16#a5#, 16#61#, 16#0e#, 16#4f#, 16#0a#, 16#33#, 16#17#,
      16#90#, 16#ca#, 16#6a#, 16#fe#, 16#66#, 16#2f#, 16#c4#, 16#3c#, 16#ed#,
      16#36#, 16#6e#, 16#87#, 16#cd#, 16#38#, 16#f6#, 16#ca#, 16#43#, 16#29#,
      16#0e#, 16#6d#, 16#cb#, 16#d1#, 16#05#, 16#97#, 16#be#, 16#2c#, 16#65#,
      16#12#, 16#ce#, 16#47#, 16#98#, 16#6f#, 16#4e#, 16#83#, 16#0a#, 16#81#,
      16#12#, 16#4c#, 16#bb#, 16#87#, 16#13#, 16#30#, 16#25#, 16#59#, 16#3a#,
      16#7c#, 16#33#, 16#df#, 16#2d#, 16#f0#, 16#d2#, 16#52#, 16#6a#, 16#6f#,
      16#de#, 16#5d#, 16#16#, 16#04#, 16#3a#, 16#84#, 16#85#, 16#68#, 16#9a#,
      16#80#, 16#c4#, 16#09#, 16#ff#, 16#15#, 16#92#, 16#d8#, 16#b8#, 16#cb#,
      16#34#, 16#a2#, 16#31#, 16#d6#, 16#ff#, 16#55#, 16#9f#, 16#c7#, 16#fb#,
      16#fd#, 16#12#, 16#ed#, 16#dc#, 16#66#, 16#97#, 16#45#, 16#f3#, 16#1d#,
      16#68#, 16#d2#, 16#05#, 16#8e#, 16#1a#, 16#d0#, 16#65#, 16#c8#, 16#a6#,
      16#49#, 16#e3#, 16#09#, 16#da#, 16#c7#, 16#61#, 16#eb#, 16#81#, 16#2f#,
      16#18#, 16#25#, 16#3d#, 16#0c#, 16#72#, 16#7d#, 16#a1#, 16#7e#, 16#9a#,
      16#33#, 16#97#, 16#59#, 16#6e#, 16#6d#, 16#64#, 16#f1#, 16#27#, 16#d7#,
      16#9f#, 16#e4#, 16#2b#, 16#83#, 16#71#, 16#a0#, 16#3d#, 16#cd#, 16#84#,
      16#c6#, 16#8b#, 16#df#, 16#fd#, 16#68#, 16#ab#, 16#79#, 16#08#, 16#37#,
      16#b9#, 16#a4#, 16#d6#, 16#00#, 16#36#, 16#e9#, 16#ae#, 16#e2#, 16#31#,
      16#57#, 16#4b#, 16#96#, 16#1f#, 16#31#, 16#c2#, 16#9c#, 16#e9#, 16#01#,
      16#9f#, 16#42#, 16#6d#, 16#b0#, 16#f1#, 16#71#, 16#8f#, 16#67#, 16#f0#,
      16#e2#, 16#96#, 16#4d#, 16#4f#, 16#ea#, 16#79#, 16#fc#, 16#ea#, 16#98#,
      16#d8#, 16#8f#, 16#ba#, 16#08#, 16#54#, 16#1e#, 16#8e#, 16#ef#, 16#2c#,
      16#71#, 16#95#, 16#1b#, 16#b2#, 16#d2#, 16#ee#, 16#ca#, 16#b4#, 16#a4#,
      16#46#, 16#ad#, 16#2d#, 16#fc#, 16#88#, 16#d9#, 16#78#, 16#0a#, 16#56#,
      16#10#, 16#71#, 16#5f#, 16#ee#, 16#8c#, 16#16#, 16#a3#, 16#0f#, 16#95#,
      16#68#, 16#1b#, 16#8a#, 16#02#, 16#f3#, 16#8a#, 16#53#, 16#1c#, 16#0f#,
      16#1d#, 16#04#, 16#26#, 16#f1#, 16#fc#, 16#f6#, 16#37#, 16#c5#, 16#9a#,
      16#81#, 16#d9#, 16#1b#, 16#ad#, 16#b3#, 16#f9#, 16#80#, 16#ec#, 16#a5#,
      16#4e#, 16#4a#, 16#f1#, 16#e2#, 16#5e#, 16#b1#, 16#5a#, 16#ea#, 16#df#,
      16#ba#, 16#64#, 16#40#, 16#3e#, 16#19#, 16#36#, 16#bc#, 16#b7#, 16#a8#,
      16#f7#, 16#c3#, 16#e4#, 16#4b#, 16#91#, 16#c3#, 16#d4#, 16#cb#, 16#a6#,
      16#44#, 16#28#, 16#4e#, 16#81#, 16#3f#, 16#f5#, 16#fc#, 16#97#, 16#94#,
      16#40#, 16#6b#, 16#b5#, 16#38#, 16#a9#, 16#dd#, 16#b7#, 16#c4#, 16#d9#,
      16#83#, 16#58#, 16#77#, 16#76#, 16#8f#, 16#dc#, 16#9f#, 16#31#, 16#89#,
      16#1f#, 16#44#, 16#6b#, 16#28#, 16#a0#, 16#ac#, 16#06#, 16#0e#, 16#75#,
      16#5f#, 16#52#, 16#53#, 16#f4#, 16#84#, 16#46#, 16#a6#, 16#ac#, 16#6e#,
      16#16#, 16#fc#, 16#95#, 16#22#, 16#0e#, 16#3a#, 16#83#, 16#e6#, 16#5e#,
      16#68#, 16#9d#, 16#d2#, 16#ae#, 16#6e#, 16#b2#, 16#e4#, 16#92#, 16#67#,
      16#78#, 16#fe#, 16#ed#, 16#3f#, 16#05#, 16#ea#, 16#31#, 16#9c#, 16#5d#,
      16#30#, 16#bb#, 16#20#, 16#bd#, 16#99#, 16#4c#, 16#14#, 16#35#, 16#dc#,
      16#e7#, 16#a5#, 16#d1#, 16#6e#, 16#b1#, 16#83#, 16#2a#, 16#bf#, 16#6b#,
      16#67#, 16#e1#, 16#9c#, 16#ba#, 16#fd#, 16#6e#);
   --  Other pubvalue (MODP-3072).

   Xa_Ref : constant String := "59c2a472fcedb982ac701f3ccd75670789709f189ccb85"
     & "f6ad90fd5eeb8ebcc2a0fb0f0e97a64a8faf8288ad3002e7aa547ea3b4815d524106be"
     & "6a650a9c56b41e1fb22ef3c971798db841177cfde964388e52bfa7479ab759211b9532"
     & "139272e532fb1d1a5aaba003542b6e8594c88af4401c409e2363a0eb922ec19effd865"
     & "83584208dea053e57f1e6fdf8b137d77d1f01776ef0ae8196457b5cc442eb6a2f2e4d8"
     & "1407a1d5d4c0c3cf0b2fdbd5a959c3dc9054cb7650cdba1503987ab12c1bca4e9ebc09"
     & "e7e74801c3e5e0dfae7718f651e45cd1073e3835a87556f4bc5b4bf0146d40623de582"
     & "b70da9b2170e063f1078ae77934defd3dcac5a9bbc3b3a48cd532295c30d82b61e3a12"
     & "e4ba9e49674975594a933ebc8ba13ae3047dc361ef6cdab5425ac2b0f292665de3f7b3"
     & "cb713d843b8e697bb7957f210f28ccb715f8ad676c3da6e98f0e90484b1cca5a264317"
     & "8ffa348834ff0c15297b94cfd3214ecfe2630b32c054e47e31ab736b5cb39ac26aba21"
     & "0ca18e89c7f98833693e384e534cf105fd70a0c38684a3df9e2d049e01a28c974a192b"
     & "9388b79b71754b1eb4e26ca503a823b59d7eb5589ad42aa990a572159798d3198d2392"
     & "23e254f8844856fc92ac758a8f5c6ea05d49ba0257176b295682821b0bca03743da5e8"
     & "c5a5b371390a2ec1e4bcf5062d15e45cf0a02ff6c709e99d5f1a309155386a0e8385";
   --  Xa (secret) reference value.

   Xa_3072_Ref : constant String := "7ae89bd53b3c67c82dfb14d8be5ab36aa36684524"
     & "85091a3159163ae13cff7827df49e8f8eb388348f5e21ffca3e0d00aad286b13c08796"
     & "8fe9de0ed8d0ba5e1a146afb95176dc31da331dc145ac9e622c99f023268bd91b5e95d"
     & "e381b8c96aa45833ce9403e770d82c9d7b5d9c72d29e79d4c13740f3874fcdb7c9a947"
     & "fffc3cf1b3fe74e95225bf1a4b386e58e977e0bf7473a5d3a7d0b100f99a0f7d087dfd"
     & "f6558793ba032b1b6fff61e0d342dc681dbd47a8715f014babc477970ae253ef252242"
     & "b7bece3dbd597e3cdd9d63265979b85a6a69f5ecec878a325af4e7150a8ea5449373d7"
     & "b8ed62be2a48fae94de9d4b2cce85d956a1255da93e8780fa60dff1278801b3ea15443"
     & "f996b1b45b77d6a69abd7bbdef1b5bd6a899ae6a9df7714885a456dcb4860240026886"
     & "7b124fb2354e2f5cb02217666cb6f2f9face4988113cf53e4eeae8bd1c0eab93816d19"
     & "e317cdd9de472a166047da964347002777d017159506fe7304a1a43d80869d6b829edd"
     & "b2a12f3ec3bb24a2e50bcaa2097";
   --  Xa (secret) reference value (MODP-3072).

   Ya_Ref : constant String := "89b56822a8725fb0ed02ab54a85d9d3b14b1887be71aa9"
     & "01aafa9a7a84ff1d1d473d30253ed0a1f2ed52bb1dabe59a6f1f24fac9819edd3f646f"
     & "bfdb26b8796c97b3d945a44a1b5c1787c7d210e8cc3d636d2baf131898c3688bbab29d"
     & "21d826f731f182a52202d8dea33592f60b04f58c9da924b5e0d8794e56e0da41fb65d1"
     & "8efef373c409e974c10a622085d454fc4f04570bea1fdf4ec868b6af00e05a26286ebf"
     & "aa6da99a7e9e26d215eaf4c8918024bc0f5e4f3561bac5a917f54fef8f923cd82bffcf"
     & "4617a39de93854189a362b203192816d99445c7e94869ecc3db68b87bcee93bad04d0a"
     & "311914dcea22b98518319e5b7d4a0111fd63fcb515329cc84d5a08c0ad62b0386a888f"
     & "d5679b97ce631a1db06f0575294244f3ee72c1582c2f53e0c6ed2eafb1a4c4b195f874"
     & "56fd21336ba9ed8a00e7267df1381e1e6020dcc4a7d3fb292b7b674bbdacdc4a960f25"
     & "1b0f68de84369294889af24c5d18d496ed86922b75f20e44a4f90d2b33f278bd04597f"
     & "f91e9d52eb2b305d9d0d70b9d9985a3b123a912d629340696217d44063e3dba4c34560"
     & "c57254674d02ed947d854c8cd7959bc9b322e156dc945336d5979009341a1e377aac6b"
     & "03cad0501d4f31760123ee9528a1ebb29a7b7d4ed159a697cf44b4bcfc10c0876d9e9b"
     & "40162924a238ff8179160ee53e2e369f56ed1dc10a4767882659fb76ab7939663e99";
   --  Ya (my pubvalue) reference value.

   Ya_3072_Ref : constant String := "4d5d2bce0e20b869b134fa0e91aa02a4e2ba5d5dd"
     & "52f2a1bf1577a49a56e05637d3be87dba03cc139a8a21a4d476d2e94315f276c2df1fd"
     & "cf40603d3c546dd3f21bcdd7a3ee10f68cc78eb99d0ccc18065a68f18d084d7fca2175"
     & "2e9b23d07578bed312c62effed2337ecfeabf4f2f384b1e1aac2a752f7b5da2a0dbdd0"
     & "3d16f885f0af057cff12c837020b6e37000ce02debc6f4592cd889f07882cc481dcc2a"
     & "b59c2755abacf11b91ada5b14a087d30dce9d03c3b35a6560b99f5876e30b9c8fc37b6"
     & "62ca8c631bcfb6c55ab1724004e0177b4f0ffc73eacfab307162e55db9c60b6ac25957"
     & "7bd481d94f22b4649607e37c5ca358f9f08393c46f242945a435fa76f84478ca044d90"
     & "ebcec0ab4caf7ca7d42168343a30891a8f09d8c59e499bb230228f240fbc2d3d1426a3"
     & "bd16828e6a63c0c78729379c8d070cf30692d12a9eff7c5bc90991845136e5d7e3f454"
     & "a66d5a2d4cc89e1d9f618483692edefb5e2dc9cedbcab0154d88bfcfe7bd84232252e6"
     & "49e93dcbd40c6ccab2930f528f7";
   --  Ya (my pubvalue) reference value (MODP-3072).

   Zz_Ref : constant String := "2a5f4772f638b8a27a6569b63800f5923372f917bf81ea"
     & "b0e36f54b9f70a3ed8366ef34cbc104c68c06d4761eed7328b828ec0513c7e3467d910"
     & "f6a7c38b77c53da8207f2d4e641d6d0a71a194d58df4b66b20cd03917172737212efe2"
     & "84b75f72149ea6f0bf62bf941835021a4942188ec6f16b784b124379de7e2884e4311c"
     & "a8645070449e93d2ffa73d651ae25c3769746f5a35e228bc66ee47f88530725b07dc2a"
     & "99746d86d37a1c25e30e20071e231475df18b5946116e1f9d3b10f918a55037214ff00"
     & "d7700a1594b75949ca5b20f8565381973ca2c87cbd7c690571c1f464fb30a873318b8c"
     & "684a8c86c91d16f1374daaf2751602943189b14d9ff960d599afa454a685625d64b4e3"
     & "7fba1b5c5b501dd45ccf3a0d3a7af135cb5bf9aa425738d7dae41acaef210fb55f0e7a"
     & "c8c5f852e1ef542b55a80ca9e07601df94189f772087e522e2bc5f0093cc14c932464f"
     & "98e3265e6e6618a541d49f41dea41a18375a91bb457416adff330d44afdf11a90d9286"
     & "13a361dcb6d15637bfd48aff04ee0d759e88b10e68f0fd0c66c6b167ce34df4ea87bb2"
     & "ffade0c175fcee5c436101c28af0ab4e98f9f3cda27224271d802a089d271e9c801b3b"
     & "8d8d8456478904ece2997cf18e379c0253894f54855e6407b11d7ff8e66bc01bf48352"
     & "8c9710b13e607b89146c708f4f58410ed96da64ee4c8c9e8074c24b9ca0dc38ed15e";
   --  Zz (shared secret) reference value.

   Zz_3072_Ref : constant String := "1efb13cd74b842d46d12b3136d701578076647647"
     & "684f0880f7beed1e02415b8afcc41a968961cfc872d26cee91f98480bf41098a61aa42"
     & "786d64a6dc75a456eb96fd1347f1374a3c747fcacacae3113ebc041f3b7e1ae9313283"
     & "51c7399c2c77a54bc09367cd6eaecdeda0329faf94c5d8285986a66c12ceddb55011b7"
     & "ec24e52f307a227057cd1f7e6cf14ec25a3ce00a0ccaef74fdb6f3a4a4816c2e9b2102"
     & "972a87e735e63c908648c74049b97f7c31f9748bbbdf21d9513c2e5e5a0fd930afe9df"
     & "f46bd50a63cf631d54d75502783f9b4d6b328746ba7785f0d68fd2b1926ec0160594b0"
     & "b9d520c9ec3d4e327e33d2e1d73b386eb69464a70a29a7e0ea2ac0871f88566c7d1dbf"
     & "101a67c491376aefa2b311af698c527a8d3a60ac7f5d02b4567b7f60b9e34afee8ceaf"
     & "5609ce1baad1a509e2a9cc3b67ac169bc31d8d1dbf12002ca95711c34b52dc62518dd6"
     & "3f9fd5f7b60537954acf7ca26d288497e87d5983c395d47d4b682adf30d05809d4bf80"
     & "546be3e0ce3f5e6c86ba656ef40";
   --  Zz (shared secret) reference value (MODP-3072).

   -------------------------------------------------------------------------

   procedure Compute_Xa_Ya_Zz
   is
      Xa_Bytes, Ya_Bytes, Zz_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 512);
   begin
      Diffie_Hellman.Compute_Xa_Ya
        (Dha_Id       => Diffie_Hellman.Dha_Modp_4096,
         Random_Bytes => Random_Chunk,
         Xa           => Xa_Bytes,
         Ya           => Ya_Bytes);
      Assert (Condition => Utils.To_Hex_String (Input => Xa_Bytes) = Xa_Ref,
              Message   => "Xa mismatch");
      Assert (Condition => Utils.To_Hex_String (Input => Ya_Bytes) = Ya_Ref,
              Message   => "Ya mismatch");

      Diffie_Hellman.Compute_Zz (Dha_Id => Diffie_Hellman.Dha_Modp_4096,
                                 Xa     => Xa_Bytes,
                                 Yb     => Yb_Chunk,
                                 Zz     => Zz_Bytes);
      Assert (Condition => Utils.To_Hex_String (Input => Zz_Bytes) = Zz_Ref,
              Message   => "Zz mismatch");
   end Compute_Xa_Ya_Zz;

   -------------------------------------------------------------------------

   procedure Compute_Xa_Ya_Zz_Modp_3072
   is
      Xa_Bytes, Ya_Bytes, Zz_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 384);
   begin
      Diffie_Hellman.Compute_Xa_Ya
        (Dha_Id       => Diffie_Hellman.Dha_Modp_3072,
         Random_Bytes => Random_3072_Chunk,
         Xa           => Xa_Bytes,
         Ya           => Ya_Bytes);
      Assert
        (Condition => Utils.To_Hex_String (Input => Xa_Bytes) = Xa_3072_Ref,
         Message   => "Xa mismatch (MODP-3072)");
      Assert
        (Condition => Utils.To_Hex_String (Input => Ya_Bytes) = Ya_3072_Ref,
         Message   => "Ya mismatch (MODP-3072)");

      Diffie_Hellman.Compute_Zz (Dha_Id => Diffie_Hellman.Dha_Modp_3072,
                                 Xa     => Xa_Bytes,
                                 Yb     => Yb_3072_Chunk,
                                 Zz     => Zz_Bytes);
      Assert
        (Condition => Utils.To_Hex_String (Input => Zz_Bytes) = Zz_3072_Ref,
         Message   => "Zz mismatch");
   end Compute_Xa_Ya_Zz_Modp_3072;

   -------------------------------------------------------------------------

   procedure Get_Group_Size
   is
   begin
      Assert (Condition => Diffie_Hellman.Get_Group_Size
              (Dha_Id => Diffie_Hellman.Dha_Modp_4096) = 512,
              Message   => "MODP-4096 group size mismatch");
      Assert (Condition => Diffie_Hellman.Get_Group_Size
              (Dha_Id => Diffie_Hellman.Dha_Modp_3072) = 384,
              Message   => "MODP-3072 group size mismatch");
   end Get_Group_Size;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Diffie-Hellman tests");
      T.Add_Test_Routine
        (Routine => Compute_Xa_Ya_Zz'Access,
         Name    => "Compute xa, ya and zz");
      T.Add_Test_Routine
        (Routine => Compute_Xa_Ya_Zz_Modp_3072'Access,
         Name    => "Compute xa, ya and zz (MODP-3072)");
      T.Add_Test_Routine
        (Routine => Invalid_Yb'Access,
         Name    => "Public value validation");
      T.Add_Test_Routine
        (Routine => Unsupported_DH_Group'Access,
         Name    => "Unsupported DH group");
      T.Add_Test_Routine
        (Routine => Get_Group_Size'Access,
         Name    => "Get DH group size");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Invalid_Yb
   is
      Zz_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 512);
      Yb       : Tkmrpc.Types.Byte_Sequence (1 .. 512) := (others => 0);
   begin
      begin
         Diffie_Hellman.Compute_Zz (Dha_Id => Diffie_Hellman.Dha_Modp_4096,
                                    Xa     => Random_Chunk,
                                    Yb     => Yb,
                                    Zz     => Zz_Bytes);
         Fail (Message => "Exception expected");

      exception
         when Diffie_Hellman.DH_Error => null;
      end;

      Yb (Yb'Last) := 1;
      begin
         Diffie_Hellman.Compute_Zz (Dha_Id => Diffie_Hellman.Dha_Modp_4096,
                                    Xa     => Random_Chunk,
                                    Yb     => Yb,
                                    Zz     => Zz_Bytes);
         Fail (Message => "Exception expected");

      exception
         when Diffie_Hellman.DH_Error => null;
      end;

      Yb := (others => 16#ff#);
      begin
         Diffie_Hellman.Compute_Zz (Dha_Id => Diffie_Hellman.Dha_Modp_4096,
                                    Xa     => Random_Chunk,
                                    Yb     => Yb,
                                    Zz     => Zz_Bytes);
         Fail (Message => "Exception expected");

      exception
         when Diffie_Hellman.DH_Error => null;
      end;
   end Invalid_Yb;

   -------------------------------------------------------------------------

   procedure Unsupported_DH_Group
   is
      Xa_Bytes, Ya_Bytes, Zz_Bytes : Tkmrpc.Types.Byte_Sequence (1 .. 512);
   begin
      begin
         Diffie_Hellman.Compute_Xa_Ya (Dha_Id       => 0,
                                       Random_Bytes => Random_Chunk,
                                       Xa           => Xa_Bytes,
                                       Ya           => Ya_Bytes);
         Fail (Message => "Exception expected");

      exception
         when Diffie_Hellman.DH_Error => null;
      end;

      begin
         Diffie_Hellman.Compute_Zz (Dha_Id => 0,
                                    Xa     => Xa_Bytes,
                                    Yb     => Yb_Chunk,
                                    Zz     => Zz_Bytes);
         Fail (Message => "Exception expected");

      exception
         when Diffie_Hellman.DH_Error => null;
      end;
   end Unsupported_DH_Group;

end Diffie_Hellman_Tests;
