using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

using Model.DataModel;

namespace Model.Helpers
{
    internal sealed class FileParser
    {
        private readonly PermissionResolver _permissionResolver = new PermissionResolver(WindowsIdentity.GetCurrent());
        private readonly string _path;

        public FileParser(string path)
        {
            _path = path;
        }

        public Node Parse()
        {
            var info = new FileInfo(_path);
            var accessControl = info.GetAccessControl();

            var sid = accessControl.GetOwner(typeof (SecurityIdentifier));
            var ntAccount = sid.Translate(typeof (NTAccount));

            var owner = ntAccount;
            var permission = _permissionResolver.CheckPermissions(accessControl);
            var isFolder = (info.Attributes & FileAttributes.Directory) == FileAttributes.Directory;
            return new Node
                       {
                           Attributes = info.Attributes.ToString(),
                           Created = info.CreationTimeUtc,
                           LastAccess = info.LastAccessTimeUtc,
                           LastModify = info.LastWriteTimeUtc,
                           Name = info.Name,
                           Owner = owner.Value,
                           Permissions = permission,
                           Size = isFolder ? 0 : info.Length,
                           NodeType = isFolder ? NodeType.FolderCaption : NodeType.File
                       };
        }

        private sealed class PermissionResolver
        {
            private readonly IdentityReference[] _memberInGroups;

            /// <exception cref="ArgumentNullException"></exception>
            public PermissionResolver(WindowsIdentity identity)
            {
                if (identity == null || identity.Groups == null)
                {
                    throw new ArgumentNullException("identity");
                }

                _memberInGroups = new IdentityReference[identity.Groups.Count];
                for (int i = 0; i < identity.Groups.Count; i++)
                {
                    _memberInGroups[i] = identity.Groups[i].Translate(typeof(NTAccount));
                }
            }

            public string CheckPermissions(FileSecurity accessControl)
            {
                FileSystemRights res = 0;
                foreach (FileSystemAccessRule fileSystemAccessRule in accessControl.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    if (!_memberInGroups.Contains(fileSystemAccessRule.IdentityReference))
                    {
                        continue;
                    }

                    res |= fileSystemAccessRule.FileSystemRights;
                }

                return res == 0 ? "access denied" : res.ToString();
            }
        }
    }
}
