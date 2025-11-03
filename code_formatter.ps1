# Before submitting a PR, run this script to format the source code.

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
        -not $shouldExclude
    } | 
    ForEach-Object { 
        clang-format -i $_.FullName
        Write-Host "Formatted: $($_.FullName)"
    }

Write-Host "Code formatting complete!"
