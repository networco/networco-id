# Use the .NET 10 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG APP_VERSION=0.0.1.0
WORKDIR /app

# Copy everything first to ensure restore has all context
COPY . .
RUN dotnet restore src/NetworcoId/NetworcoId.csproj

# Build and publish
WORKDIR /app/src/NetworcoId
RUN dotnet publish -c Release -o /app/publish --no-restore /p:InformationalVersion=$APP_VERSION /p:Version=$APP_VERSION

# Final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN apk add --no-cache icu-libs
WORKDIR /app
COPY --from=build /app/publish .

# Environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
EXPOSE 8080

ENTRYPOINT ["dotnet", "NetworcoId.dll"]
