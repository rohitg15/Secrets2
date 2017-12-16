using System;
using Utils;

namespace Models
{
    public class Secret
    {

        public string secretId { get; set; }

        public string b64EncryptedSecret { get; set; }
        
        public string b64Salt { get; set; }

        public DateTime createdTimeStamp { get; set; }

        public DateTime updatedTimeStamp { get; set; }

        public string tag { get; set; }

        public string mac { get; set; }

        public Secret(string secretId, string b64EncryptedSecret, string b64Salt, DateTime createdTs, DateTime updatedTs, string tag, string mac)
        {
            this.secretId = Preconditions.CheckNotNull(secretId);
            this.b64EncryptedSecret = Preconditions.CheckNotNull(b64EncryptedSecret);
            this.b64Salt = Preconditions.CheckNotNull(b64Salt);
            this.createdTimeStamp = Preconditions.CheckNotNull(createdTs);
            this.updatedTimeStamp = Preconditions.CheckNotNull(updatedTs);
            this.tag = Preconditions.CheckNotNull(tag);
            this.mac = Preconditions.CheckNotNull(mac);
        }
    }
}
