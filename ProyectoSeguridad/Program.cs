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
        Console.WriteLine("secrets.json cargado (desarrollo local)");
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

Console.WriteLine($"Railway configurado: {(tieneRailway ? "SI" : "NO")}");
Console.WriteLine($"Local configurado: {(tieneLocal ? "SI" : "NO")}");

// ======================================================================
// CONFIGURAR RATE LIMITING PROTECCIÓN CONTRA ATAQUES MASIVOS
// ======================================================================
// Protege contra scripts automatizados que simulan múltiples usuarios
// Límites muy estrictos para endpoints críticos (login, registro, encriptación)
builder.Services.AddRateLimiter(options =>
{
    // Límite global por dirección IP con detección de scripts
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        // Obtener IP del cliente (o "unknown" si no se puede determinar)
        var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Obtener User-Agent para detectar scripts automatizados
        var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
        var esDispositivoMovil = EsDispositivoMovil(userAgent);
        var esScriptAutomatizado = EsUserAgentDeScript(userAgent);

        var ruta = httpContext.Request.Path.ToString().ToLowerInvariant();
        var metodo = httpContext.Request.Method;

        // DETECCIÓN Y BLOQUEO DE SCRIPTS AUTOMATIZADOS
        // Si detecta User-Agent de script conocido, bloqueo total
        if (esScriptAutomatizado)
        {
            // Bloqueo total por 30 minutos para scripts detectados
            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"BLOQUEO_SCRIPT_{ipAddress}",
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,
                    PermitLimit = 1, // Solo 1 petición permitida
                    Window = TimeSpan.FromMinutes(30), // Bloqueo por 30 minutos
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0 // Sin cola, rechazar inmediatamente
                });
        }

        // PROTECCIÓN EXTREMA PARA LOGIN Y REGISTRO (POST)
        // Estos endpoints son objetivos comunes de ataques de fuerza bruta
        if ((ruta.Contains("/account/login") || ruta.Contains("/account/registro")) && metodo == "POST")
        {
            // Límite muy estricto: solo 3 intentos por minuto por IP
            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"{ipAddress}_CRITICO_AUTENTICACION",
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,
                    PermitLimit = 3, // Solo 3 intentos por minuto
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0 // Sin cola
                });
        }

        // PROTECCIÓN PARA OPERACIONES DE ENCRIPTACIÓN/DESENCRIPTACIÓN (POST)
        // Estas operaciones son costosas en recursos
        if (ruta.Contains("/encriptacion") && metodo == "POST")
        {
            // Token bucket limiter para control más fino
            return RateLimitPartition.GetTokenBucketLimiter(
                partitionKey: $"{ipAddress}_ENCRIPTACION",
                factory: partition => new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 5, // Máximo 5 tokens
                    TokensPerPeriod = 1, // Recarga 1 token cada 30 segundos
                    ReplenishmentPeriod = TimeSpan.FromSeconds(30),
                    AutoReplenishment = true,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0 // Sin cola
                });
        }

        // Límite general para todas las demás rutas
        // Más estricto que antes para prevenir ataques DDoS
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"{ipAddress}_GENERAL",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 20, // 20 peticiones por minuto (reducido de 30)
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2 // Cola pequeña
            });
    });

    // Configurar respuesta personalizada para errores 429 (Too Many Requests)
    // Mensaje especial para scripts detectados
    options.OnRejected = async (context, token) =>
    {
        // Detectar si es dispositivo móvil
        var userAgent = context.HttpContext.Request.Headers["User-Agent"].ToString();
        var esScriptAutomatizado = EsUserAgentDeScript(userAgent);

        context.HttpContext.Response.StatusCode = 429; // Status Code 429: Too Many Requests

        // Mensajes diferentes según el tipo de detección
        string message;
        if (esScriptAutomatizado)
        {
            message = "ACTIVIDAD AUTOMATIZADA DETECTADA. Acceso bloqueado por seguridad.";
        }
        else
        {
            message = "Demasiadas peticiones. Por favor, espera un minuto.";
        }

        await context.HttpContext.Response.WriteAsync(message, cancellationToken: token);
    };

    Console.WriteLine("Rate Limiting configurado con proteccion anti-scripts: 3 login/min, 20 peticiones/min");
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
// SERVICIO JWT para autenticación
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
// CONFIGURAR AUTENTICACIÓN JWT
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

// Habilitar autorización 
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
    Console.WriteLine($"Railway detectado - Puerto: {port}");
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

// ======================================================================
// FUNCIÓN NUEVA: DETECTAR SCRIPTS AUTOMATIZADOS
// ======================================================================
/// <summary>
/// Detecta si el User-Agent corresponde a un script automatizado o bot
/// Basado en patrones comunes de herramientas de automatización, hacking y scraping
/// </summary>
/// <param name="userAgent">Cadena User-Agent del navegador/cliente</param>
/// <returns>True si es script automatizado, False si es navegador legítimo</returns>
static bool EsUserAgentDeScript(string userAgent)
{
    if (string.IsNullOrEmpty(userAgent))
        return true; // Sin User-Agent = sospechoso

    var userAgentLower = userAgent.ToLower();

    // ======================================================================
    // PERMITIR NAVEGADORES COMUNES (INCLUYENDO LOCALHOST)
    // ======================================================================
    var navegadoresPermitidos = new[]
    {
        // Firefox y derivados
        "mozilla", "firefox", "gecko",
        
        // Chrome/Chromium y derivados
        "chrome", "chromium", "crios", "brave", "vivaldi",
        "edge", "edg", "opera", "opr", "safari",
        
        // Safari y WebKit
        "safari", "webkit", "applewebkit",
        
        // Internet Explorer
        "msie", "trident",
        
        // Móviles
        "mobile", "android", "iphone", "ipad",
        
        // Testing local
        "postmanruntime", "insomnia", "thunder client",
        "swagger", "openapi"
    };

    // Si es un navegador conocido, NO es script
    foreach (var navegador in navegadoresPermitidos)
    {
        if (userAgentLower.Contains(navegador))
        {
            Console.WriteLine($"✅ Navegador permitido: {navegador}");
            return false; // NO es script
        }
    }

    // ======================================================================
    // SOLO BLOQUEAR HERRAMIENTAS DE ATAQUE REALES
    // ======================================================================
    var herramientasAtaque = new[]
    {
        // Herramientas de hacking específicas
        "sqlmap", "nikto", "hydra", "medusa", "patator",
        "brutus", "dirb", "gobuster", "ffuf", "wfuzz",
        "arjun", "xsstrike", "commix", "wapiti",
        
        // Network scanners maliciosos
        "masscan", "zmap", "unicornscan",
        
        // Fuerza bruta específica
        "john the ripper", "hashcat", "rainbowcrack",
        
        // Scripts personalizados maliciosos
        "attackbot", "hackbot", "exploit",
        "vulnerability scanner", "security scanner",
        
        // Muy sospechosos
        @"^\d+\.\d+\.\d+\.\d+$", // Solo IP
        @"^.{1,5}$", // Muy corto
        @"<script", "javascript:", "onload=", // Inyección
    };

    foreach (var herramienta in herramientasAtaque)
    {
        if (System.Text.RegularExpressions.Regex.IsMatch(userAgentLower, herramienta))
        {
            Console.WriteLine($"⚠️ Herramienta de ataque detectada: {herramienta}");
            return true;
        }
    }

    // ======================================================================
    // POR DEFECTO: PERMITIR (mejor permitir falso negativo que bloquear usuario)
    // ======================================================================
    Console.WriteLine($"ℹ️ User-Agent no reconocido pero PERMITIDO: {userAgent}");
    return false;
}