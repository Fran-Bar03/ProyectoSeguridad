# Etapa 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copiar archivos de proyecto (rutas relativas desde la raíz)
COPY ["ProyectoSeguridad/ProyectoSeguridad.csproj", "ProyectoSeguridad/"]
COPY ["Data/Data.csproj", "Data/"]
COPY ["Models/Models.csproj", "Models/"]
COPY ["DTOs/DTOs.csproj", "DTOs/"]

# Restaurar dependencias
RUN dotnet restore "ProyectoSeguridad/ProyectoSeguridad.csproj"

# Copiar todo el código
COPY . .

# Publicar
RUN dotnet publish "ProyectoSeguridad/ProyectoSeguridad.csproj" -c Release -o /app/publish

# Etapa 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "ProyectoSeguridad.dll"]