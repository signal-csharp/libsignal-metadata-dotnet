# Contributing

## Building

### Requirements

1. [.NET Core 3.1 or greater](https://dotnet.microsoft.com/download)
    - Opening in Visual Studio requires Visual Studio 2019 (v16.4.0) or greater

### Steps

#### Visual Studio

1. Open the libsignal-metadata-dotnet.sln in Visual Studio
2. Build the solution
3. Run the tests using the Test Explorer window

#### Command Line

1. `dotnet build`
2. `dotnet test`

## Building protobuf files

1. Ensure [protoc version 3.12.4](https://github.com/protocolbuffers/protobuf/releases/tag/v3.12.4) is on your path
2. `cd libsignal-metadata-dotnet/protobuf`
3. `./Build-Protobuf.ps1`
