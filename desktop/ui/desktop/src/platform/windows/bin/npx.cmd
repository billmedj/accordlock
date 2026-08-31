@ECHO OFF
@REM Modified by AccordLock contributors; see UPSTREAM.md.
SETLOCAL DisableDelayedExpansion

IF EXIST "%ProgramFiles%\nodejs\npx.cmd" (
    CALL "%ProgramFiles%\nodejs\npx.cmd" %*
    CALL EXIT /B %%ERRORLEVEL%%
)

IF EXIST "%ProgramFiles(x86)%\nodejs\npx.cmd" (
    CALL "%ProgramFiles(x86)%\nodejs\npx.cmd" %*
    CALL EXIT /B %%ERRORLEVEL%%
)

FOR /F "usebackq delims=" %%P IN (`WHERE.EXE npx.cmd 2^>NUL`) DO (
    IF /I NOT "%%~fP"=="%~f0" (
        CALL "%%~fP" %*
        CALL EXIT /B %%ERRORLEVEL%%
    )
)

ECHO [AccordLock] npx is required but was not found outside the application bundle. 1>&2
ECHO Install Node.js through your organization's approved system provisioning, then restart AccordLock. 1>&2
EXIT /B 127
