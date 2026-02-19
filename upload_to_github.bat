@echo off
echo ========================================
echo GitHub Upload Script
echo ========================================
echo.

REM 检查是否已初始化git
if not exist .git (
    echo Initializing Git repository...
    git init
    git config user.name "Huang HuaQuan"
    git config user.email "panghu64@users.noreply.github.com"
    git remote add origin https://github.com/panghu64/web-memory-debugger.git
) else (
    echo Git repository already initialized.
)

echo.
echo Adding all files...
git add .

echo.
echo Committing files...
git commit -m "Initial commit: Complete Web Memory Debugger project"

echo.
echo Pulling from remote (in case README was created)...
git pull origin main --allow-unrelated-histories

echo.
echo Pushing to GitHub...
git branch -M main
git push -u origin main --force

echo.
echo ========================================
echo Upload Complete!
echo Repository: https://github.com/panghu64/web-memory-debugger
echo ========================================
pause
