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

# Build and publish with mount cache
WORKDIR /app/src/NetworcoId.Worker
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet publish -c Release -o /app/publish --no-restore /p:Version=$APP_VERSION

# Final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN apk add --no-cache icu-libs
WORKDIR /app
COPY --from=build /app/publish .

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

ENTRYPOINT ["dotnet", "NetworcoId.Worker.dll"]
