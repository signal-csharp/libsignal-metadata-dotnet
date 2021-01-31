# Verify protoc is available and version is 3.12.4

$protocNugetPath = "$env:USERPROFILE/.nuget/packages/google.protobuf.tools/3.12.4/tools/windows_x64/protoc.exe"
$output = ""
try {
    $output = & $protocNugetPath --version
}
catch {
    Write-Error "Could not find protoc. Did you restore NuGet packages (dotnet restore) or is your NuGet cache not in your home directory?"
    return
}

$expectedVersion = "3.12.4"
$version = $output.Split(" ")[1]

if ($version -ne $expectedVersion) {
    Write-Error "protoc version must be $expectedVersion!"
    return
}

& $protocNugetPath --csharp_out=. .\UnidentifiedDelivery.proto

Write-Host "Done!"
