#!/bin/bash

# Script to deploy MySQL schema fix

echo "Deploying MySQL schema fix..."

# Check if we're in the correct directory
if [ ! -f "fix_mysql_schema.py" ]; then
    echo "Error: fix_mysql_schema.py not found in current directory."
    echo "Please run this script from the same directory as fix_mysql_schema.py."
    exit 1
 fi

# Check if the virtual environment exists
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
else
    echo "Warning: Virtual environment (.venv) not found."
    echo "Proceeding without virtual environment activation."
fi

# Run the fix script
echo "Running MySQL schema fix script..."
python fix_mysql_schema.py

# Check if the script ran successfully
if [ $? -eq 0 ]; then
    echo "MySQL schema fix applied successfully."
    
    # Ask if user wants to restart the application
    read -p "Do you want to restart the application now? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        # Check if this is a systemd service
        if systemctl is-active --quiet ctf_app; then
            echo "Restarting CTF application service..."
            sudo systemctl restart ctf_app
        else
            echo "No systemd service found. Please restart your application manually."
        fi
    else
        echo "Please remember to restart your application for changes to take effect."
    fi
else
    echo "Error: MySQL schema fix failed. Please check the output above for details."
    exit 1
fi

echo "Deployment complete."