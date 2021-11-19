# MacOS_Security

## #1: Encrypt a folder

Encryption of existing or new folders:

1.- Search for Disk utility in Spotlight

2.- Creating a new image:

File > New Image > Image from folder

[file](images/sel_image.png)

3.- Create a new encrypted image

Select name, encryption (AES 128 or 256 bits), select read/write schema so it can be mounted to the filesystem, and select a password.

[file](images/disk_util.png)

This will generate a new file with a .dmg extension (Never erase this file, since it's the root folder which will be decrypted and mounted temporarily into the FS)

Double click this file to enter the password, and it will be mounted into the FS.

[file](images/test_dmg)

[file](images/test_mounted)

This will be mounted until restart, so to unmount it manually we need to eject it.
