package Tkm.Logger
is
   type Log_Level is
     (Debug,
      Info,
      Notice,
      Warning,
      Error,
      Critical,
      Alert,
      Emergency);

   procedure Log
     (Level   : Log_Level := Info;
      Message : String);
   --  Log the specified message with given loglevel.

   procedure Use_Stdout;
   --  Switch to console based logging.

   procedure Stop;
   --  Stop TKM logger.

end Tkm.Logger;
