import dropbox
from config import DROPBOX_ACCESS_TOKEN

dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)

def upload_fragment(local_path, dropbox_path):
    with open(local_path, "rb") as f:
        dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

def download_fragment(dropbox_path, local_path):
    metadata, res = dbx.files_download(dropbox_path)
    with open(local_path, "wb") as f:
        f.write(res.content)
