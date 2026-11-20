@echo off
> "%TEMP%\subs_check_done.flag.tmp" echo %SUCCESS_COUNT%
move /Y "%TEMP%\subs_check_done.flag.tmp" "%TEMP%\subs_check_done.flag" >nul
