using System.Text;
using Data.Middleware;
using Data.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Data.Services;

var builder = WebApplication.CreateBuilder(args);

// ======================================================================
// 1. CONFIGURACIÓN DE VARIABLES (RAILWAY Y LOCAL)
// ======================================================================
// Railway: Usa variables de entorno del Dashboard
// Local: Usa secrets.json (solo en desarrollo)

if (builder.Environment.IsDevelopment()) // SOLO LOCAL
{
    // Cargar secrets.json para desarrollo local
    var secretPath = Path.Combine(Directory.GetCurrentDirectory(), "secret.json");
    if (File.Exists(secretPath))
    {
        builder.Configuration.AddJsonFile(secretPath, optional: false, reloadOnChange: true);
        Console.WriteLine("✓ secrets.json cargado (desarrollo local)");
    }
}

// ======================================================================
// 2. DEBUG: VER QUÉ CONFIGURACIÓN SE ESTÁ USANDO
// ======================================================================
Console.WriteLine("=== CONFIGURACIÓN DETECTADA ===");
Console.WriteLine($"Entorno: {builder.Environment.EnvironmentName}");
Console.WriteLine($"PORT: {Environment.GetEnvironmentVariable("PORT") ?? "8080 (local)"}");

// Verificar si Railway está configurado
var tieneRailway = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CONNECTION_STRING"));
var tieneLocal = !string.IsNullOrEmpty(builder.Configuration["Jwt:Key"]);

Console.WriteLine($"Railway configurado: {(tieneRailway ? "SÍ" : "NO")}");
Console.WriteLine($"Local configurado: {(tieneLocal ? "SÍ" : "NO")}");

// ======================================================================
// REGISTRAR SERVICIOS DE LA APLICACIÓN
// ======================================================================
builder.Services.AddControllersWithViews(); // Para MVC
builder.Services.AddHttpContextAccessor();  // Para acceder a HttpContext

// ======================================================================
// SERVICIOS DE BASE DE DATOS
// ======================================================================
// DatabaseService: Singleton (1 instancia para toda la app)
//  para leer de Railway primero, luego local
builder.Services.AddSingleton<IDatabaseService>(provider =>
{
    var configuracion = provider.GetRequiredService<IConfiguration>();
    var logger = provider.GetRequiredService<ILogger<DatabaseService>>();
    return new DatabaseService(configuracion, logger);
});

// Servicios Scoped (1 instancia por cada petición HTTP)
builder.Services.AddScoped<IFuerzabrutaService, FuerzabrutaService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();

// ======================================================================
// SERVICIO JWT (para autenticación)
// ======================================================================
// Registramos el servicio JWT de dos formas:
// Como interfaz IJwtService (para controladores)
// Como clase concreta JwtService (para middleware)

builder.Services.AddScoped<IJwtService, JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

builder.Services.AddScoped<JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

// ======================================================================
// CONFIGURAR AUTENTICACIÓN JWT (LO MÁS IMPORTANTE)
// ======================================================================
// ORDEN DE PRIORIDAD para la clave JWT:
//  Railway: Environment.GetEnvironmentVariable("JWT__Key") ← PRODUCCIÓN
// Local: builder.Configuration["Jwt:Key"] ← DESARROLLO
var llaveJwt = Environment.GetEnvironmentVariable("JWT__Key") ??
               builder.Configuration["Jwt:Key"] ??
               throw new Exception("ERROR: JWT Key no configurada");

// Configurar autenticación con JWT Bearer
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opciones =>
    {
        opciones.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true, // Validar que el token esté firmado
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(llaveJwt)),
            ValidateIssuer = true,      // Validar quién emitió el token
            ValidateAudience = true,    // Validar para quién es el token
            ValidateLifetime = false,   // No expira (tokens indefinidos)

            // Issuer: Quién emite el token
            ValidIssuer = Environment.GetEnvironmentVariable("JWT__Issuer") ??
                          builder.Configuration["Jwt:Issuer"] ??
                          "SecurityApp",

            // Audience: Para quién es el token
            ValidAudience = Environment.GetEnvironmentVariable("JWT__Audience") ??
                            builder.Configuration["Jwt:Audience"] ??
                            "SecurityUsers",

            ClockSkew = TimeSpan.Zero // Sin margen de error para expiración
        };

        // Extraer el token de las cookies (no del header Authorization)
        // Esto es más seguro contra ataques XSS
        opciones.Events = new JwtBearerEvents
        {
            OnMessageReceived = contexto =>
            {
                contexto.Token = contexto.Request.Cookies["jwt_token"];
                return Task.CompletedTask;
            }
        };
    });

// Habilitar autorización (requerido para [Authorize])
builder.Services.AddAuthorization();

// ======================================================================
//  CONSTRUIR LA APLICACIÓN
// ======================================================================
var app = builder.Build();

// Configurar el pipeline de peticiones HTTP
// (El orden de estos middlewares ES IMPORTANTE)

//  En producción: manejo de errores y HTTPS
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error"); // Página de error personalizada
    app.UseHsts(); // Forzar HTTPS por seguridad
}

//  Redirigir HTTP a HTTPS
app.UseHttpsRedirection();

// Servir archivos estáticos (CSS, JS, imágenes)
app.UseStaticFiles();

// IMPORTANTE PARA RAILWAY: Permitir servir archivos por defecto
app.UseDefaultFiles();

//  Configurar enrutamiento
app.UseRouting();

// Middleware personalizado: Headers de seguridad
app.UseMiddleware<SecurityHeadersMiddleware>();

// Habilitar autenticación y autorización
app.UseAuthentication();
app.UseAuthorization();

// Middleware personalizado: Validar JWT en cada petición
app.UseMiddleware<JwtMiddleware>();

// Configurar rutas por defecto (MVC)
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// ======================================================================
// INICIAR LA APLICACIÓN
// ======================================================================
// Solo para Railway, forzar el puerto
if (Environment.GetEnvironmentVariable("PORT") != null)
{
    var port = Environment.GetEnvironmentVariable("PORT");
    Console.WriteLine($"✓ Railway detectado - Puerto: {port}");
}

// Iniciar la aplicación
app.Run();