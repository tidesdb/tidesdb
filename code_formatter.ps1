# Before submitting a PR, run this script to format the source code.
# Usage: .\code_formatter.ps1

$ErrorActionPreference = 'Stop'

$EXCLUDE_DIRS = @('external', 'cmake-build-debug', '.idea', 'build', 'cmake', 'vcpkg_installed')

Get-ChildItem -Path . -Recurse -Include *.c,*.h | 
    Where-Object { 
        $file = $_
        $shouldExclude = $false
        foreach ($dir in $EXCLUDE_DIRS) {
            if ($file.FullName -like "*\$dir\*") {
                $shouldExclude = $true
                break
            }
        }
        # exclude any build-* directory (build-rel, build-wmu, ...); handle both path separators
        if (-not $shouldExclude -and
            ($file.FullName -like "*\build-*\*" -or $file.FullName -like "*/build-*/*")) {
            $shouldExclude = $true
        }
        -not $shouldExclude
    } | 
    ForEach-Object { 
        clang-format -i $_.FullName
        Write-Host "Formatted: $($_.FullName)"
    }

Write-Host "Code formatting complete!"
