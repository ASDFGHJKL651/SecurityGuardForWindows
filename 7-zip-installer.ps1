#Use English to avoid Chinese characters appearing as garbled text.
<#
.SYNOPSIS
    Downloads and silently installs 7-Zip into .\7-zip folder under the script directory
.DESCRIPTION
    Downloads the 7-Zip 26.02 installer from GitHub, silently installs it to the specified directory,
    and automatically cleans up the installer package afterwards.
.NOTES
    Administrator rights may be required (though installing to a non-system directory might not need it,
    but running as admin is recommended).
#>

# 1. Define download URL and installation directory
$downloadUrl = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.exe"
$fileName    = Split-Path -Path $downloadUrl -Leaf

# Determine script directory (fallback to current working directory if in ISE)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location -PSProvider FileSystem }
$installDir = Join-Path -Path $scriptDir -ChildPath "7-zip"

# Save downloaded file to temporary directory
$downloadDir = $env:TEMP
$filePath    = Join-Path -Path $downloadDir -ChildPath $fileName

# 2. Main process (unified error handling and cleanup)
try {
    # 2.1 Create installation directory (if it doesn't exist)
    if (-not (Test-Path -Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        Write-Host "Created installation directory: $installDir"
    }

    # 2.2 Download installer
    Write-Host "Downloading $fileName ..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath -UseBasicParsing
    Write-Host "Download completed, file temporarily stored at: $filePath"

    # 2.3 Silently install 7-Zip to target directory
    Write-Host "Silently installing 7-Zip to $installDir ..."
    $arguments = "/S /D=`"$installDir`""  # /S for silent, /D= to specify path (must be last)
    $process = Start-Process -FilePath $filePath -ArgumentList $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "Installation successful!" -ForegroundColor Green
        $exePath = Join-Path -Path $installDir -ChildPath "7z.exe"
        if (Test-Path -Path $exePath) {
            Write-Host "7z.exe installed at: $exePath"
        } else {
            Write-Host "Warning: 7z.exe not found, please check installation integrity." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Installation failed, exit code: $($process.ExitCode)" -ForegroundColor Red
    }
}
catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    # Optionally set exit code
    exit 1
}
finally {
    # 3. Clean up downloaded installer (always executed, regardless of success or failure)
    if (Test-Path -Path $filePath) {
        Remove-Item -Path $filePath -Force
        Write-Host "Deleted installer package: $filePath"
    }
}