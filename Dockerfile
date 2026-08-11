# SecureVault build & test image.
#
# SecureVault is a Windows WPF application, so it builds and tests in a WINDOWS
# container. The GUI cannot run inside a container — this image is used to verify
# that the solution restores, builds cleanly, and passes its test suite in a
# reproducible environment (CI runs the same steps on GitHub windows runners).
#
#   docker build -t securevault:ci .
#   docker run --rm securevault:ci
#
# Windows containers require a host running Windows Server 2019/2022+ with the
# Windows container feature enabled. See https://learn.microsoft.com/windows/containers/

# syntax=docker/dockerfile:1

# Build stage: restore, format-check, and compile (warnings-as-errors).
FROM mcr.microsoft.com/dotnet/sdk:6.0-windowsservercore-ltsc2022 AS build
WORKDIR /src
COPY . .
RUN dotnet restore SecureVault.sln
RUN dotnet format SecureVault.sln --verify-no-changes --no-restore
RUN dotnet build SecureVault.sln -c Release --no-restore

# Test stage: run the full suite in both configurations.
FROM build AS test
RUN dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Debug --no-build
RUN dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Release --no-build

FROM test AS final
CMD ["cmd", "/C", "echo SecureVault build image ready."]
