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

        public async Task<String> Download(string folder, string file)
        {
            var remotePath = String.Format("{0}/{1}", folder, file);
            using (var response = await dbxClient_.Files.DownloadAsync(remotePath))
            {
                // Console.WriteLine(await response.GetContentAsStringAsync());
                return await response.GetContentAsStringAsync();
            }
        }

        public async Task<List<Metadata>> ListRootFolder(string folderName)
        {
            Console.WriteLine("Folder name :" + folderName);
            var list = await dbxClient_.Files.ListFolderAsync(folderName);
            List<Metadata> remoteFiles = new List<Metadata>();

            // show folders then files
            foreach (var item in list.Entries.Where(i => i.IsFolder))
            {
                Console.WriteLine("D  {0}/", item.Name);
                
            }

            foreach (var item in list.Entries.Where(i => i.IsFile))
            {
                Console.WriteLine("F{0,8} {1}", item.AsFile.Size, item.Name);
                remoteFiles.Add(item.AsFile);
            }
            return remoteFiles;
        }

        public async Task<bool> DeleteFile(string folder, string remoteFileName)
        {
            string path = String.Format("{0}/{1}", folder, remoteFileName);
            DeleteResult delResult = await dbxClient_.Files.DeleteV2Async(path);
            return delResult.Metadata.IsDeleted;

        }


        private DropboxClient dbxClient_;
    }
}