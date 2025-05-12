@ECHO OFF

REM *********************************************************************
REM These values must be defined correctly
REM *********************************************************************

set ANT_HOME=..\tools\ant
set JAVA_HOME=..\tools\sdk\jdk-11.0.2

IF NOT EXIST %JAVA_HOME% (
	ECHO The JDK path %JAVA_HOME% does not exist, aborting.
	GOTO END
)

IF NOT EXIST %ANT_HOME% (
	ECHO The ANT executable path %ANT_HOME% does not exist, aborting.
	GOTO END
)


echo Setting environment variables
setlocal ENABLEEXTENSIONS
set PATH=%PATH%;"%ANT_HOME%\bin"
echo PATH IS NOW %PATH%
echo Running ANT script
ant

:END

ENDLOCAL