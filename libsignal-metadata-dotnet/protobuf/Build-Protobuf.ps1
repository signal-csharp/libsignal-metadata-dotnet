# Verify protoc is available on path and version is 3.12.4

$output = ""
try {
    $output = protoc --version
}
catch {
    Write-Error "Could not find protoc on path!"
    return
}

$expectedVersion = "3.12.4"
$version = $output.Split(" ")[1]

if ($version -ne $expectedVersion) {
    Write-Error "protoc version must be $expectedVersion!"
    return
}

protoc --csharp_out=. .\UnidentifiedDelivery.proto

Write-Host "Done!"
