@ECHO OFF
@REM Modified by AccordLock contributors; see UPSTREAM.md.
SETLOCAL DisableDelayedExpansion

FOR /F "usebackq delims=" %%P IN (`WHERE.EXE jbang.exe 2^>NUL`) DO (
    "%%~fP" %*
    CALL EXIT /B %%ERRORLEVEL%%
)

FOR /F "usebackq delims=" %%P IN (`WHERE.EXE jbang.cmd 2^>NUL`) DO (
    IF /I NOT "%%~fP"=="%~f0" (
        CALL "%%~fP" %*
        CALL EXIT /B %%ERRORLEVEL%%
    )
)

ECHO [AccordLock] jbang is required but was not found outside the application bundle. 1>&2
ECHO Install JBang through your organization's approved system provisioning, then restart AccordLock. 1>&2
EXIT /B 127
