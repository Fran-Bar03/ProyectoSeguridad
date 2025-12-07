using System;
using System.Collections.Generic;

namespace Data.Helpers
{
    public static class TimeZoneHelper
    {
        private static readonly TimeZoneInfo HermosilloTimeZone;

        static TimeZoneHelper()
        {
            Console.WriteLine("=== Inicializando TimeZoneHelper ===");
            Console.WriteLine($"Servidor hora actual: {DateTime.Now}");
            Console.WriteLine($"Servidor UTC actual: {DateTime.UtcNow}");

            // Intentar diferentes timezones para Hermosillo
            var timezoneCandidates = new[]
            {
                "Mountain Standard Time (Mexico)",  // Windows
                "America/Hermosillo",               // Linux/Mac
                "US/Mountain",                      // Unix alternativo
                "MST"                               // Abreviado
            };

            TimeZoneInfo foundTimeZone = null;

            foreach (var timezoneId in timezoneCandidates)
            {
                try
                {
                    var tz = TimeZoneInfo.FindSystemTimeZoneById(timezoneId);
                    Console.WriteLine($"✓ Encontrada timezone: {tz.Id} (Offset: {tz.BaseUtcOffset})");

                    // Verificar si es UTC-7 (Hermosillo)
                    if (tz.BaseUtcOffset.Hours == -7)
                    {
                        foundTimeZone = tz;
                        Console.WriteLine($"  ✓ Seleccionada: {tz.Id} es UTC-7 correcto para Hermosillo");
                        break;
                    }
                    else
                    {
                        Console.WriteLine($"  ✗ Descartada: No es UTC-7 (es {tz.BaseUtcOffset})");
                    }
                }
                catch (TimeZoneNotFoundException)
                {
                    Console.WriteLine($"✗ No encontrada: {timezoneId}");
                    continue;
                }
            }

            // Si no se encontró, crear una personalizada
            if (foundTimeZone == null)
            {
                Console.WriteLine("✗ No se encontró timezone adecuada, creando personalizada UTC-7");
                foundTimeZone = TimeZoneInfo.CreateCustomTimeZone(
                    "America/Hermosillo_Custom",
                    TimeSpan.FromHours(-7),
                    "America/Hermosillo (Custom)",
                    "America/Hermosillo (Custom)");
            }

            HermosilloTimeZone = foundTimeZone;
            Console.WriteLine($"=== TimeZone Helper listo: {HermosilloTimeZone.Id} ===");
        }

        // Método para obtener la zona horaria
        public static TimeZoneInfo GetHermosilloTimeZone()
        {
            return HermosilloTimeZone;
        }

        public static DateTime ToHermosilloTime(DateTime utcDateTime)
        {
            return TimeZoneInfo.ConvertTimeFromUtc(utcDateTime, HermosilloTimeZone);
        }

        public static DateTime NowInHermosillo()
        {
            return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, HermosilloTimeZone);
        }

        // Método para convertir de Hermosillo a UTC
        public static DateTime ToUtcTime(DateTime hermosilloDateTime)
        {
            return TimeZoneInfo.ConvertTimeToUtc(hermosilloDateTime, HermosilloTimeZone);
        }

        // Método para debug
        public static string GetDebugInfo()
        {
            var serverTime = DateTime.Now;
            var serverUtc = DateTime.UtcNow;
            var hermosilloTime = NowInHermosillo();

            return $"Servidor: {serverTime:HH:mm:ss} ({TimeZoneInfo.Local.Id}), " +
                   $"UTC: {serverUtc:HH:mm:ss}, " +
                   $"Hermosillo: {hermosilloTime:HH:mm:ss}, " +
                   $"Diferencia Servidor-Hermosillo: {(serverTime - hermosilloTime):hh\\:mm}";
        }
    }
}