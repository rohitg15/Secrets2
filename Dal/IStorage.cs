using System;
using Models;
using System.Collections.Generic;


namespace Dal
{
    public interface IStorage
    {
        Secret ReadSecret(string secretId);
        void WriteSecret(Secret secret);
        List<Secret> ListSecrets();
    }
}
