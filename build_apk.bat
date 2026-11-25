@echo off
setlocal
set PATH=%PATH%;C:\Users\arabi\AppData\Local\Android\Sdk\ndk\29.0.13846066\toolchains\llvm\prebuilt\windows-x86_64\bin
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-17.0.21.10002-hotspot
cd /d D:\4. Projects\6. NexPass\Mobile\Android\src-tauri
cargo build --target aarch64-linux-android --release
if errorlevel 1 (
    echo Cargo build failed
    exit /b 1
)
cd /d D:\4. Projects\6. NexPass\Mobile\Android
npx tauri android build --apk
if errorlevel 1 (
    echo Tauri build failed
    exit /b 1
)
echo Build completed successfully!
