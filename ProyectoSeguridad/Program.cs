using System.Text;
using Data.Middleware;
using Data.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Data.Services;

var builder = WebApplication.CreateBuilder(args);

// Cargar archivo secret.json si existe
// Este archivo contiene configuraciones sensibles como claves JWT
var secretPath = Path.Combine(Directory.GetCurrentDirectory(), "secret.json");
if (File.Exists(secretPath))
{
    builder.Configuration.AddJsonFile(secretPath, optional: false, reloadOnChange: true);
}

// Configurar Kestrel para VirtualBox en entorno de produccion
// Permite conexiones desde cualquier IP en puertos 5000 (HTTP) y 5001 (HTTPS)
if (builder.Environment.IsProduction())
{
    builder.WebHost.ConfigureKestrel(opcionServidor =>
    {
        opcionServidor.ListenAnyIP(5000);   // HTTP
        opcionServidor.ListenAnyIP(5001);   // HTTPS
    });
}

// Configurar servicios de la aplicacion
builder.Services.AddControllersWithViews();

// Acceso al HttpContext para servicios que necesitan contexto HTTP
builder.Services.AddHttpContextAccessor();

// Patron de diseño singleton para manejar una sola instancia a la base de datos
// Garantiza conexiones eficientes y controladas
builder.Services.AddSingleton<IDatabaseService>(provedopr =>
{
    var configuracion = provedopr.GetRequiredService<IConfiguration>();
    var logger = provedopr.GetRequiredService<ILogger<DatabaseService>>();
    return new DatabaseService(configuracion, logger);
});

// Servicios con scope por request para manejo de estado independiente
builder.Services.AddScoped<IFuerzabrutaService, FuerzabrutaService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();

// Para la interfaz IJwtService (usada por controladores)
builder.Services.AddScoped<IJwtService, JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

// Para la clase concreta JwtService (usada por el middleware)
builder.Services.AddScoped<JwtService>(sp =>
    new JwtService(
        sp.GetRequiredService<IConfiguration>(),
        sp.GetRequiredService<IHttpContextAccessor>()
    ));

// Configurar autenticacion JWT
// Obtener clave JWT desde configuracion, requerida para firma de tokens
var LlaveJwt = builder.Configuration["Jwt:Key"];
if (string.IsNullOrEmpty(LlaveJwt))
    throw new Exception("JWT Key no configurada en secret.json");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opcion =>
    {
        opcion.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(LlaveJwt)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "SecurityApp",
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? "SecurityUsers",
            ClockSkew = TimeSpan.Zero  // Sin tolerancia para expiracion
        };

        // Extraer el token de la cookie en lugar del header Authorization
        // Esto proporciona mejor proteccion contra XSS
        opcion.Events = new JwtBearerEvents
        {
            OnMessageReceived = contexto =>
            {
                // Leer token desde la cookie 'jwt_token'
                contexto.Token = contexto.Request.Cookies["jwt_token"];
                return Task.CompletedTask;
            }
        };
    });

// Configurar autorizacion por defecto
builder.Services.AddAuthorization();

// Construir aplicacion
var app = builder.Build();

// Configurar pipeline de peticiones HTTP
if (!app.Environment.IsDevelopment())
{
    // En produccion, usar pagina de error personalizada
    app.UseExceptionHandler("/Home/Error");

    // HSTS: Forzar HTTPS por 30 dias (recomendado para produccion)
    app.UseHsts();
}

// Redireccionar HTTP a HTTPS para mayor seguridad
app.UseHttpsRedirection();

// Servir archivos estaticos (CSS, JS, imagenes)
app.UseStaticFiles();

// Configurar enrutamiento de peticiones
app.UseRouting();

// Middleware personalizado para headers de seguridad
// Agrega protecciones contra XSS, clickjacking y cache no deseado
app.UseMiddleware<SecurityHeadersMiddleware>();

// Habilitar autenticacion JWT configurada previamente
app.UseAuthentication();

// Habilitar autorizacion basada en roles/claims
app.UseAuthorization();

// Middleware personalizado para validacion JWT en cada request
// Maneja redirecciones y validaciones adicionales
app.UseMiddleware<JwtMiddleware>();

// Configurar rutas por defecto
// Todas las peticiones sin ruta especifica iran a Account/Login
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Iniciar aplicacion
app.Run();