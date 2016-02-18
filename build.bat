@echo off
title Build Forensic.py
color 0b

set CWD=%~dp0
cd /d "%CWD%"

IF EXIST dist (
	RMDIR /S /Q dist
)

c:\Python34\python.exe setup.py py2exe

REM del dist\icudt53.dll
REM del dist\icuin53.dll
REM del dist\icuuc53.dll
REM del dist\Qt5Core.dll
REM del dist\Qt5Gui.dll
REM del dist\Qt5Widgets.dll

echo Done.
ping localhost -n 20 >NUL
