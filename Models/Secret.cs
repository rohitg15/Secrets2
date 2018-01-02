using System;
using Utils;

namespace Models
{
    public class Secret
    {

        public string b64AlgIds { get; set; }
        public string secretId { get; set; }

        public string b64EncryptedSecret { get; set; }
        
        public string b64Salt { get; set; }

        public string b64IvOrNonce { get; set; }

        public DateTime createdTimeStamp { get; set; }

        public string tag { get; set; }

        public string b64Mac { get; set; }

        public Secret(string b64AlgIds, string secretId, string b64EncryptedSecret, string b64Salt, string b64IvOrNonce, DateTime createdTs, string tag, string b64Mac)
        {
            this.b64AlgIds = Preconditions.CheckNotNull(b64AlgIds);
            this.secretId = Preconditions.CheckNotNull(secretId);
            this.b64EncryptedSecret = Preconditions.CheckNotNull(b64EncryptedSecret);
            this.b64Salt = Preconditions.CheckNotNull(b64Salt);
            this.b64IvOrNonce = Preconditions.CheckNotNull(b64IvOrNonce);
            this.createdTimeStamp = Preconditions.CheckNotNull(createdTs);
            this.tag = Preconditions.CheckNotNull(tag);
            this.b64Mac = Preconditions.CheckNotNull(b64Mac);
        }
    }
}
