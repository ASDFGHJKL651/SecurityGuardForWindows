# install-g++.ps1
#Use English to avoid Chinese characters appearing as garbled text
# Automatically downloads MinGW-w64 (g++ compiler) and installs it into .\mingw\ subdirectory
# By default adds the bin directory to user PATH after installation

param(
    [string]$InstallDir = $null,               # If not specified, defaults to mingw under script directory
    [string]$DownloadUrl = "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-14.0.0-ucrt-r1/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r1.zip",
    [switch]$AddToPath = $true,                # Enable automatic PATH addition by default
    [switch]$SystemPath = $false               # Add to system PATH (requires admin rights)
)

# Color output helper
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# ----- Determine script root and installation directory -----
if ([string]::IsNullOrEmpty($InstallDir)) {
    $ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    $InstallDir = Join-Path $ScriptRoot "mingw"
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

Write-ColorOutput "=== MinGW-w64 (g++) Auto Installer ===" "Cyan"
Write-ColorOutput "Script directory: $ScriptRoot" "Cyan"
Write-ColorOutput "Installation directory (absolute): $InstallDir" "Cyan"

# 1. Create installation directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-ColorOutput "[OK] Created directory: $InstallDir" "Green"
}

# 2. Download MinGW-w64 archive
$zipFile = Join-Path $env:TEMP "mingw-w64.zip"
Write-ColorOutput "Downloading MinGW-w64 ..." "Yellow"
Write-ColorOutput "Download URL: $DownloadUrl" "Gray"

try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipFile -UseBasicParsing
    Write-ColorOutput "[OK] Download completed: $zipFile" "Green"
} catch {
    Write-ColorOutput "[ERROR] Download failed: $($_.Exception.Message)" "Red"
    exit 1
}

# 3. Extract to installation directory
Write-ColorOutput "Extracting to $InstallDir ..." "Yellow"
try {
    Expand-Archive -Path $zipFile -DestinationPath $InstallDir -Force
    Write-ColorOutput "[OK] Extraction completed" "Green"
} catch {
    Write-ColorOutput "[ERROR] Extraction failed: $($_.Exception.Message)" "Red"
    exit 1
}

# 4. Clean temporary file
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue

# 5. Locate bin directory
$binPaths = Get-ChildItem -Path $InstallDir -Recurse -Filter "g++.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.Directory.FullName }

if ($binPaths) {
    $binDir = $binPaths | Select-Object -First 1
    Write-ColorOutput "[OK] Found g++.exe at: $binDir" "Green"
    
    # 6. Verify g++
    $gppPath = Join-Path $binDir "g++.exe"
    if (Test-Path $gppPath) {
        Write-ColorOutput "[OK] g++ installed successfully!" "Green"
        & $gppPath --version
    } else {
        Write-ColorOutput "[WARN] g++.exe not found" "Yellow"
    }
    
    # 7. Automatically add to PATH (enabled by default)
    if ($AddToPath) {
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Determine target scope (Machine or User)
        $targetScope = "User"
        if ($SystemPath) {
            if ($isAdmin) {
                $targetScope = "Machine"
                Write-ColorOutput "[INFO] Adding to system PATH (admin rights detected)" "Cyan"
            } else {
                Write-ColorOutput "[WARN] Not running as administrator, cannot add to system PATH. Fallback to user PATH." "Yellow"
                $targetScope = "User"
            }
        } else {
            Write-ColorOutput "[INFO] Adding to user PATH" "Cyan"
        }

        # Get current PATH and deduplicate
        $currentPath = [Environment]::GetEnvironmentVariable("Path", $targetScope)
        $pathList = $currentPath -split ';' | Where-Object { $_ -ne "" }
        if ($pathList -notcontains $binDir) {
            $newPath = $currentPath + ";" + $binDir
            [Environment]::SetEnvironmentVariable("Path", $newPath, $targetScope)
            Write-ColorOutput "[OK] Added to $targetScope PATH: $binDir" "Green"
            Write-ColorOutput "[Hint] Please restart your terminal for PATH changes to take effect" "Yellow"
        } else {
            Write-ColorOutput "[OK] Path already exists in PATH" "Green"
        }
    }
} else {
    Write-ColorOutput "[WARN] g++.exe not found, please check extraction result" "Yellow"
}

Write-ColorOutput "=== Installation Complete ===" "Cyan"
Write-ColorOutput "To manually add to PATH, add the following directory to your environment variables:" "Yellow"
if ($binPaths) {
    Write-ColorOutput "  $binDir" "White"
} else {
    Write-ColorOutput "  Please manually locate the bin directory under $InstallDir" "White"
}