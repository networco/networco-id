# Use the .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG APP_VERSION=0.0.1.0
WORKDIR /app

# Copy csproj files and restore as distinct layers for better caching
COPY ["src/NetworcoId/NetworcoId.csproj", "src/NetworcoId/"]
COPY ["src/NetworcoId.Core/NetworcoId.Core.csproj", "src/NetworcoId.Core/"]
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet restore "src/NetworcoId/NetworcoId.csproj"

# Copy remaining source code
COPY . .

# Build and publish with mount cache
WORKDIR /app/src/NetworcoId
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet publish -c Release -o /app/publish --no-restore /p:InformationalVersion=$APP_VERSION /p:Version=$APP_VERSION

# Final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN apk add --no-cache icu-libs
WORKDIR /app
COPY --from=build /app/publish .

# Copy the development certificate for data protection (optional, for dev-in-docker)
# Note: Ensure the file exists and is not excluded by .dockerignore
COPY src/NetworcoId/dataprotection.pfx .

# Environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
EXPOSE 8080

ENTRYPOINT ["dotnet", "NetworcoId.dll"]
