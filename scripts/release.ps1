[CmdletBinding()]
param(
    [ValidatePattern('^v?\d+\.\d+\.\d+$')]
    [string]$Version,

    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repositoryRoot
try {
    $versionLine = Select-String -LiteralPath 'main.go' -Pattern 'const Version = "(v[^"]+)"'
    if (-not $versionLine.Matches.Success) {
        throw 'Could not read Version from main.go.'
    }
    $sourceTag = $versionLine.Matches[0].Groups[1].Value
    $requestedTag = if ($Version) { 'v' + $Version.TrimStart('v') } else { $sourceTag }
    if ($requestedTag -ne $sourceTag) {
        throw "Requested version $requestedTag does not match main.go $sourceTag."
    }

    $notesFile = "docs/releases/$requestedTag.md"
    if (-not (Test-Path -LiteralPath $notesFile -PathType Leaf)) {
        throw "Tracked release notes are missing: $notesFile"
    }
    git ls-files --error-unmatch -- $notesFile *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Release notes are not tracked: $notesFile"
    }
    if (git status --porcelain) {
        throw 'The worktree must be clean before dispatching a release.'
    }
    if ((git branch --show-current).Trim() -ne 'master') {
        throw 'Release dispatch must run from the master branch.'
    }

    gh --version *> $null
    gh auth status *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'GitHub CLI authentication is required.'
    }
    git fetch --quiet origin master
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not fetch origin/master.'
    }
    $head = (git rev-parse HEAD).Trim()
    $remoteHead = (git rev-parse origin/master).Trim()
    if ($head -ne $remoteHead) {
        throw 'Local master and origin/master must point to the same commit.'
    }

    $publishValue = if ($Publish) { 'true' } else { 'false' }
    gh workflow run release.yml --ref master `
        --field "version=$($requestedTag.TrimStart('v'))" `
        --field "publish=$publishValue"
    if ($LASTEXITCODE -ne 0) {
        throw 'GitHub release workflow dispatch failed.'
    }

    $mode = if ($Publish) { 'publish' } else { 'dry-run' }
    Write-Host "Dispatched $requestedTag release workflow in $mode mode."
    Write-Host 'Track it with: gh run watch --exit-status'
}
finally {
    Pop-Location
}
