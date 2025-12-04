using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Data.Helpers
{
   public static class TimeZoneHelper
    {
        private static readonly TimeZoneInfo HermosilloTimeZone;

        static TimeZoneHelper()
        {
            try
            {
                // Para Windows
                HermosilloTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Mountain Standard Time (Mexico)");
            }
            catch
            {
                try
                {
                    // Para Linux/Mac
                    HermosilloTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Hermosillo");
                }
                catch
                {
                    // Si falla, crear una zona personalizada UTC-7
                    HermosilloTimeZone = TimeZoneInfo.CreateCustomTimeZone(
                        "America/Hermosillo",
                        TimeSpan.FromHours(-7),
                        "America/Hermosillo",
                        "America/Hermosillo");
                }
            }
        }

        public static DateTime ToHermosilloTime(DateTime utcDateTime)
        {
            return TimeZoneInfo.ConvertTimeFromUtc(utcDateTime, HermosilloTimeZone);
        }

        public static DateTime NowInHermosillo()
        {
            return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, HermosilloTimeZone);
        }
    }
}
