using System;
using Models;
using System.Linq;
using System.Collections.Generic;
using System.Security;
using Utils;

namespace Dal
{

    public class DropboxStorage : IStorage
    {

        public DropboxStorage(SecureString accessToken)
        {
            this.dbx_ = new DropboxUtil(accessToken);
        }

        public string GetProviderName()
        {
            return "Dropbox";
        }

        public void DeleteSecret(string secretId)
        {
            throw new NotImplementedException();
        }

        public List<Secret> ListSecrets()
        {
            throw new NotImplementedException();
        }

        public Secret ReadSecret(string secretId)
        {
            throw new NotImplementedException();
        }

        public void WriteSecret(Secret secret, bool overwrite = false)
        {
            this.dbx_.Upload("/SecretDb", "test2", "hello world 2").Wait();
        }

        private DropboxUtil dbx_;
    }
}