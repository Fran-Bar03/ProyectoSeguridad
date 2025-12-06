using System.Text;
using Data.Middleware;
using Data.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Data.Services;

var builder = WebApplication.CreateBuilder(args);

// ======================================================================
// CONFIGURACIÓN DE CARGA DE ARCHIVOS SECRETOS
// ======================================================================
// Cargar archivo secret.json si existe para configuraciones sensibles
// Este archivo contiene claves JWT y cadenas de conexión a BD
// COMENTADO PARA VERCEL: En Vercel usamos Variables de Entorno
// var secretPath = Path.Combine(Directory.GetCurrentDirectory(), "secret.json");
// if (File.Exists(secretPath))
// {
//     builder.Configuration.AddJsonFile(secretPath, optional: false, reloadOnChange: true);
// }

// ======================================================================
// CONFIGURACIÓN DE KESTREL PARA ENTORNO PRODUCCIÓN
// ======================================================================
// Configurar para permitir conexiones desde cualquier IP en VirtualBox
// COMENTADO PARA VERCEL: Vercel maneja el servidor automáticamente
// if (builder.Environment.IsProduction())
// {
//     builder.WebHost.ConfigureKestrel(opcionServidor =>
//     {
//         opcionServidor.ListenAnyIP(5000);   // HTTP
//         opcionServidor.ListenAnyIP(5001);   // HTTPS
//     });
// }

// ======================================================================
// DEBUG: Verificar configuración (QUITAR después del deploy exitoso)
// ======================================================================
Console.WriteLine("=== VERCEL ENV VARS ===");
Console.WriteLine($"PORT: {Environment.GetEnvironmentVariable("PORT")}");
Console.WriteLine($"CONNECTION_STRING: {Environment.GetEnvironmentVariable("CONNECTION_STRING")?.Substring(0, Math.Min(20, Environment.GetEnvironmentVariable("CONNECTION_STRING")?.Length ?? 0))}...");
Console.WriteLine($"JWT__Key: {(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("JWT__Key")) ? "NO" : "SÍ")}");

// ======================================================================
// REGISTRO DE SERVICIOS DE LA APLICACIÓN
// ======================================================================
builder.Services.AddControllersWithViews();

// Acceso al HttpContext para servicios que necesitan contexto HTTP
builder.Services.AddHttpContextAccessor();

// ======================================================================
// SERVICIOS DE BASE DE DATOS Y NEGOCIO
// ======================================================================

// Servicio Singleton: Una sola instancia para toda la aplicación
// Gestión eficiente de conexiones a PostgreSQL
builder.Services.AddSingleton<IDatabaseService>(provider =>
{
    var configuracion = provider.GetRequiredService<IConfiguration>();
    var logger = provider.GetRequiredService<ILogger<DatabaseService>>();
    return new DatabaseService(configuracion, logger);
});

// Servicios Scoped: Una instancia por request HTTP
// Estado independiente para cada petición del usuario
builder.Services.AddScoped<IFuerzabrutaService, FuerzabrutaService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();

// ======================================================================
// REGISTRO  DE JwtService
// ======================================================================

// 1. Para la interfaz IJwtService (usada por controladores)
builder.Services.AddScoped<IJwtService, JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

// 2. Para la clase concreta JwtService (usada por el middleware)
builder.Services.AddScoped<JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

// ======================================================================
// CONFIGURACIÓN DE AUTENTICACIÓN JWT
// ======================================================================
// Obtener clave JWT desde configuración (requerida para firmar tokens)
// MODIFICADO PARA VERCEL: Compatible con Variables de Entorno (JWT__Key)
var llaveJwt = builder.Configuration["Jwt:Key"] ??
               builder.Configuration["JWT__Key"] ??
               throw new Exception("JWT Key no configurada. Configura JWT__Key en Vercel");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opciones =>
    {
        opciones.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(llaveJwt)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false, // Sin expiración para tokens indefinidos
            // MODIFICADO PARA VERCEL: Compatible con Variables de Entorno
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? builder.Configuration["JWT__Issuer"] ?? "SecurityApp",
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? builder.Configuration["JWT__Audience"] ?? "SecurityUsers",
            ClockSkew = TimeSpan.Zero // Sin tolerancia para expiración
        };

        // Extraer token de cookie en lugar de header Authorization
        // Mejor protección contra XSS que Authorization header
        opciones.Events = new JwtBearerEvents
        {
            OnMessageReceived = contexto =>
            {
                contexto.Token = contexto.Request.Cookies["jwt_token"];
                return Task.CompletedTask;
            }
        };
    });

// Configurar autorización por defecto
builder.Services.AddAuthorization();

// ======================================================================
// CONSTRUCCIÓN Y CONFIGURACIÓN DE LA APLICACIÓN
// ======================================================================
var app = builder.Build();

// Configurar pipeline de peticiones HTTP
if (!app.Environment.IsDevelopment())
{
    // En producción: página de error personalizada
    app.UseExceptionHandler("/Home/Error");
    // HSTS: Forzar HTTPS por 30 días
    app.UseHsts();
}

// Redirección HTTP a HTTPS para mayor seguridad
app.UseHttpsRedirection();

// Servir archivos estáticos (CSS, JS, imágenes)
app.UseStaticFiles();

// Configurar enrutamiento de peticiones
app.UseRouting();

// Middleware personalizado: Headers de seguridad
// Agrega protecciones contra XSS, clickjacking y cache
app.UseMiddleware<SecurityHeadersMiddleware>();

// Habilitar autenticación y autorización JWT
app.UseAuthentication();
app.UseAuthorization();

// Middleware personalizado: Validación JWT en cada request
// Maneja redirecciones y validaciones adicionales
app.UseMiddleware<JwtMiddleware>();

// Configurar rutas por defecto
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// ======================================================================
// INICIAR APLICACIÓN - MODIFICADO PARA VERCEL
// ======================================================================
// Vercel asigna un puerto dinámico a través de la variable PORT
// Esto reemplaza a: app.Run();
var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port))
{
    // Modo Vercel: usar puerto dinámico
    app.Run($"http://0.0.0.0:{port}");
}
else
{
    // Modo local: usar configuración normal
    app.Run();
}