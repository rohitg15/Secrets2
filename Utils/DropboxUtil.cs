using System;
using System.Collections.Generic;
using Dropbox.Api;
using System.Threading.Tasks;
using System.IO;
using System.Text;
using Dropbox.Api.Files;
using System.Linq;
using System.Security;

namespace Utils
{
        public class DropboxUtil
    {
        public DropboxUtil(SecureString accessToken)
        {
            this.dbxClient_ = new DropboxClient(StringUtils.GetStringFromSecureString(accessToken));
        }

        ~DropboxUtil()
        {
            this.dbxClient_.Dispose();
        }

        public async Task Upload(string folder, string file, string content)
        {
            using (var mem = new MemoryStream(Encoding.UTF8.GetBytes(content)))
            {
                Console.WriteLine("Saving File... {0}/{1} with {2}", folder, file, content);
                var updated = await dbxClient_.Files.UploadAsync(
                    folder + "/" + file,
                    WriteMode.Overwrite.Instance,
                    body: mem);
                Console.WriteLine("Saved {0}/{1} rev {2}", folder, file, updated.Rev);
            }
        }

        public async Task Download(string folder, string file)
        {
            using (var response = await dbxClient_.Files.DownloadAsync(folder + "/" + file))
            {
                Console.WriteLine(await response.GetContentAsStringAsync());
            }
        }

        public async Task ListRootFolder()
        {
            var list = await dbxClient_.Files.ListFolderAsync(string.Empty);

            // show folders then files
            foreach (var item in list.Entries.Where(i => i.IsFolder))
            {
                Console.WriteLine("D  {0}/", item.Name);
            }

            foreach (var item in list.Entries.Where(i => i.IsFile))
            {
                Console.WriteLine("F{0,8} {1}", item.AsFile.Size, item.Name);
            }
        }


        private DropboxClient dbxClient_;
    }
}