<#
.SYNOPSIS
    下载并静默安装 7-Zip 到当前脚本目录下的 .\7-zip 文件夹
.DESCRIPTION
    从 GitHub 下载 7-Zip 26.02 安装包，静默安装到指定目录，完成后自动清理安装包。
.NOTES
    需要管理员权限（安装到非系统目录可能不需要，但建议以管理员身份运行）。
#>

# 1. 定义下载链接与安装目录
$downloadUrl = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.exe"
$fileName    = Split-Path -Path $downloadUrl -Leaf

# 确定脚本所在目录（若在 ISE 中运行则使用当前工作目录）
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location -PSProvider FileSystem }
$installDir = Join-Path -Path $scriptDir -ChildPath "7-zip"

# 下载文件保存至临时目录
$downloadDir = $env:TEMP
$filePath    = Join-Path -Path $downloadDir -ChildPath $fileName

# 2. 主流程（统一错误处理和清理）
try {
    # 2.1 创建安装目录（如果不存在）
    if (-not (Test-Path -Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        Write-Host "已创建安装目录: $installDir"
    }

    # 2.2 下载安装包
    Write-Host "正在下载 $fileName ..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath -UseBasicParsing
    Write-Host "下载完成，文件暂存于: $filePath"

    # 2.3 静默安装 7-Zip 到目标目录
    Write-Host "正在静默安装 7-Zip 到 $installDir ..."
    $arguments = "/S /D=`"$installDir`""  # 安装参数：/S 静默，/D= 指定路径（必须放最后）
    $process = Start-Process -FilePath $filePath -ArgumentList $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "安装成功！" -ForegroundColor Green
        $exePath = Join-Path -Path $installDir -ChildPath "7z.exe"
        if (Test-Path -Path $exePath) {
            Write-Host "7z.exe 已安装至: $exePath"
        } else {
            Write-Host "警告：未找到 7z.exe，请检查安装是否完整。" -ForegroundColor Yellow
        }
    } else {
        Write-Host "安装失败，退出代码: $($process.ExitCode)" -ForegroundColor Red
    }
}
catch {
    Write-Host "发生错误: $_" -ForegroundColor Red
    # 可根据需要添加退出码
    exit 1
}
finally {
    # 3. 清理下载的安装包（无论成功或失败都执行）
    if (Test-Path -Path $filePath) {
        Remove-Item -Path $filePath -Force
        Write-Host "已删除安装包: $filePath"
    }
}