using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CNX.Shared.Helpers
{
    public static class GuidHelper
    {
        //http://stackoverflow.com/questions/665417/sequential-guid-in-linq-to-sql/2187898#2187898
        public static Guid NewComb()
        {
            byte[] destinationArray = Guid.NewGuid().ToByteArray();
            DateTime time = new DateTime(0x76c, 1, 1);
            DateTime now = DateTime.UtcNow;
            TimeSpan span = new TimeSpan(now.Ticks - time.Ticks);
            TimeSpan timeOfDay = now.TimeOfDay;
            byte[] bytes = BitConverter.GetBytes(span.Days);
            byte[] array = BitConverter.GetBytes((long)(timeOfDay.TotalMilliseconds / 3.333333));
            Array.Reverse(bytes);
            Array.Reverse(array);
            Array.Copy(bytes, bytes.Length - 2, destinationArray, destinationArray.Length - 6, 2);
            Array.Copy(array, array.Length - 4, destinationArray, destinationArray.Length - 4, 4);
            return new Guid(destinationArray);
        }


        public static DateTime GetDate(this Guid guid)
        {
            byte[] sourceArray = guid.ToByteArray();
            DateTime timeReference = new DateTime(0x76c, 1, 1);
            byte[] days = BitConverter.GetBytes(0);
            byte[] time = BitConverter.GetBytes(0L);
            Array.Copy(sourceArray, sourceArray.Length - 6, days, days.Length - 2, 2);
            Array.Copy(sourceArray, sourceArray.Length - 4, time, time.Length - 4, 4);
            Array.Reverse(days);
            Array.Reverse(time);
            var dayOffset = BitConverter.ToInt32(days, 0);
            var timeOffset = BitConverter.ToInt64(time, 0);
            return timeReference.AddDays(dayOffset).AddMilliseconds(timeOffset * 3.333333);

        }

        public static string Nonce
        {
            get { return NewComb().ToString().Replace("-", ""); }
        }

        public static string ToNonce(this Guid guid)
        {
            return guid.ToString().Replace("-", "");
        }
    }
}