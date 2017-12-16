using System;

namespace Utils
{
    public class Preconditions
    {
        public static T CheckNotNull<T>(T obj)
        {
            if ( Nullable.GetUnderlyingType(typeof(T)) == null  && obj == null )
            {
                string name = nameof(obj);
                throw new ArgumentNullException(String.Format("Error: {0} of type {1} is null.", name, typeof(T).FullName));
            }
            return obj;
        }
    }
}