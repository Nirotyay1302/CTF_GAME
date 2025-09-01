@echo off
echo Deploying MySQL schema fix...

:: Check if we're in the correct directory
if not exist fix_mysql_schema.py (
    echo Error: fix_mysql_schema.py not found in current directory.
    echo Please run this script from the same directory as fix_mysql_schema.py.
    exit /b 1
)

:: Check if the virtual environment exists
if exist .venv (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo Warning: Virtual environment (.venv) not found.
    echo Proceeding without virtual environment activation.
)

:: Run the fix script
echo Running MySQL schema fix script...
python fix_mysql_schema.py

:: Check if the script ran successfully
if %ERRORLEVEL% EQU 0 (
    echo MySQL schema fix applied successfully.
    
    :: Ask if user wants to restart the application
    set /p restart="Do you want to restart the application now? (y/n): "
    if /i "%restart%"=="y" (
        echo Please restart your application manually or through your service manager.
    ) else (
        echo Please remember to restart your application for changes to take effect.
    )
) else (
    echo Error: MySQL schema fix failed. Please check the output above for details.
    exit /b 1
)

echo Deployment complete.
pause