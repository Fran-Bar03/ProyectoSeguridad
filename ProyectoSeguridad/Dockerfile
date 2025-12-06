# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files
COPY ["ProyectoSeguridad/ProyectoSeguridad.csproj", "ProyectoSeguridad/"]
COPY ["Data/Data.csproj", "Data/"]
COPY ["Models/Models.csproj", "Models/"]
COPY ["DTOs/DTOs.csproj", "DTOs/"]

# Restore dependencies
RUN dotnet restore "ProyectoSeguridad/ProyectoSeguridad.csproj"

# Copy source code (excluding Dockerfile and other ignored files)
COPY ProyectoSeguridad/ ProyectoSeguridad/
COPY Data/ Data/
COPY Models/ Models/
COPY DTOs/ DTOs/

# Publish application
RUN dotnet publish "ProyectoSeguridad/ProyectoSeguridad.csproj" -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "ProyectoSeguridad.dll"]