# Use the .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG APP_VERSION=0.0.1.0
WORKDIR /app

# Copy csproj files and restore as distinct layers for better caching
COPY ["src/NetworcoId.Worker/NetworcoId.Worker.csproj", "src/NetworcoId.Worker/"]
COPY ["src/NetworcoId.Core/NetworcoId.Core.csproj", "src/NetworcoId.Core/"]
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet restore "src/NetworcoId.Worker/NetworcoId.Worker.csproj"

# Copy remaining source code
COPY . .

# Build and publish with mount cache.
# NOTE: no --no-restore. The NuGet packages live in an ephemeral BuildKit cache
# mount that can be evicted between the restore and publish RUNs; with
# --no-restore that surfaces as "Package … was not found, might have been
# deleted since NuGet restore" and fails the build non-deterministically.
# Letting publish restore is idempotent (cache-backed) and self-heals.
WORKDIR /app/src/NetworcoId.Worker
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet publish -c Release -o /app/publish /p:Version=$APP_VERSION

# Final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN apk add --no-cache icu-libs
WORKDIR /app
COPY --from=build /app/publish .

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

ENTRYPOINT ["dotnet", "NetworcoId.Worker.dll"]
