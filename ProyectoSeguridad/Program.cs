using System.Text;
using Data.Middleware;
using Data.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Data.Services;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ======================================================================
//  CONFIGURACIÓN DE VARIABLES (RAILWAY Y LOCAL)
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
// VER QUÉ CONFIGURACIÓN SE ESTÁ USANDO
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
// 3. CONFIGURAR RATE LIMITING PROTECCIÓN CONTRA ABUSO/DDoS
// ======================================================================
// Protege contra ataques de fuerza bruta y abuso en endpoints críticos
// Limita: 15 peticiones por minuto por IP, 10 para encriptación/desencriptación
// MODIFICADO: Ahora detecta dispositivos móviles y aplica límites específicos
builder.Services.AddRateLimiter(options =>
{
    // Límite global por dirección IP y tipo de dispositivo
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        // Obtener IP del cliente (o "unknown" si no se puede determinar)
        var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Obtener User-Agent para detectar tipo de dispositivo
        var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
        var esDispositivoMovil = EsDispositivoMovil(userAgent);

        var ruta = httpContext.Request.Path.ToString().ToLowerInvariant();

        // Límites más estrictos para operaciones de encriptación/desencriptación (POST)
        // MODIFICADO: Límites diferentes para móviles vs escritorio
        if (ruta.Contains("/encriptacion") && httpContext.Request.Method == "POST")
        {
            // Para móviles: límite más bajo (8 por minuto)
            // Para escritorio: límite normal (10 por minuto)
            var partitionKey = esDispositivoMovil ?
                $"{ipAddress}_mobile_encriptacion" :
                $"{ipAddress}_desktop_encriptacion";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: partitionKey,
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,          // Recarga automática de límites
                    PermitLimit = esDispositivoMovil ? 8 : 10, // Límites específicos por dispositivo
                    Window = TimeSpan.FromMinutes(1),  // Ventana de 1 minuto
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst, // Procesar en orden
                    QueueLimit = esDispositivoMovil ? 1 : 2 // Cola más pequeña para móviles
                });
        }

        // Límite general para todas las demás rutas
        // MODIFICADO: Límites ajustados según tipo de dispositivo
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"{ipAddress}_{(esDispositivoMovil ? "mobile" : "desktop")}",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = esDispositivoMovil ? 12 : 15, // Móviles: 12, Escritorio: 15
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = esDispositivoMovil ? 2 : 3 // Cola más pequeña para móviles
            });
    });

    // Configurar respuesta personalizada para errores 429 (Too Many Requests)
    // MODIFICADO: Mensajes diferentes para dispositivos móviles
    options.OnRejected = async (context, token) =>
    {
        // Detectar si es dispositivo móvil
        var userAgent = context.HttpContext.Request.Headers["User-Agent"].ToString();
        var esDispositivoMovil = EsDispositivoMovil(userAgent);

        context.HttpContext.Response.StatusCode = 429; // Status Code 429: Too Many Requests

        var message = esDispositivoMovil
            ? "⚠️ Demasiadas peticiones desde tu dispositivo móvil. Espera un minuto."
            : "⚠️ Demasiadas peticiones. Por favor, espera un minuto.";

        await context.HttpContext.Response.WriteAsync(message, cancellationToken: token);
    };

    Console.WriteLine("✓ Rate Limiting configurado: 10 encriptaciones/min (escritorio), 8 (móviles), 15 peticiones/min (escritorio), 12 (móviles)");
});

// ======================================================================
// REGISTRAR SERVICIOS DE LA APLICACIÓN
// ======================================================================
builder.Services.AddControllersWithViews(); // Para MVC
builder.Services.AddHttpContextAccessor();  // Para acceder a HttpContext

// ======================================================================
// SERVICIOS DE BASE DE DATOS
// ======================================================================
// DatabaseService: Singleton (1 instancia para toda la app)
// para leer de Railway primero, luego local
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
// MODIFICADO: Ahora incluye información de dispositivo móvil en los tokens
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

// ======================================================================
// HABILITAR RATE LIMITING 
// ======================================================================
app.UseRateLimiter();

// Middleware personalizado: Headers de seguridad
// MODIFICADO: Ahora incluye headers específicos para dispositivos móviles
app.UseMiddleware<SecurityHeadersMiddleware>();

// Habilitar autenticación y autorización
app.UseAuthentication();
app.UseAuthorization();

// Middleware personalizado: Validar JWT en cada petición
// MODIFICADO: Ahora detecta y maneja dispositivos móviles
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

// ======================================================================
// FUNCIÓN AUXILIAR PARA DETECTAR DISPOSITIVOS MÓVILES
// ======================================================================
/// <summary>
/// Detecta si el User-Agent corresponde a un dispositivo móvil o tablet
/// Usa una lista de cadenas comunes en User-Agents de dispositivos móviles
/// </summary>
/// <param name="userAgent">Cadena User-Agent del navegador</param>
/// <returns>True si es dispositivo móvil o tablet, False si es escritorio</returns>
static bool EsDispositivoMovil(string userAgent)
{
    if (string.IsNullOrEmpty(userAgent))
        return false;

    var userAgentLower = userAgent.ToLower();

    // Lista de dispositivos móviles y tablets
    var dispositivosMoviles = new[]
    {
        "mobile", "android", "iphone", "ipad", "ipod",
        "blackberry", "windows phone", "webos", "opera mini",
        "iemobile", "kindle", "silk", "tablet", "touch"
    };

    return dispositivosMoviles.Any(dispositivo =>
        userAgentLower.Contains(dispositivo));
}