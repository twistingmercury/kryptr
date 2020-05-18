# kryptr...

...is a file encryption tool that I use to protect sensitive documents.  Sure, there are other apps for password management, but I wanted to create my own.  It is also an exercise for me to explore Go's crypto packages.

## Using kryptr

### Initializing kryptr

When first lauching krytpr, you need to initialize it so it can create a unique encryption key.  The key itself is protected by an RSA key pair that is also generated and used to protect the configuration (which at this time only contains the file encryption key).

Do this by running the command `kryptr --init`

```
$ kryptr -i

>>>>>>>>>>>>>>>>>>>>>>>>>>*<<<<<<<<<<<<<<<<<<<<<<<<<<
 _    _   ___  ______  _   _  _____  _   _  _____  _
| |  | | / _ \ | ___ \| \ | ||_   _|| \ | ||  __ \| |
| |  | |/ /_\ \| |_/ /|  \| |  | |  |  \| || |  \/| |
| |/\| ||  _  ||    / | .   |  | |  | .   || | __ | |
\  /\  /| | | || |\ \ | |\  | _| |_ | |\  || |_\ \|_|
 \/  \/ \_| |_/\_| \_|\_| \_/ \___/ \_| \_/ \____/(_)
       THIS WILL GENERATE NEW SECURITY KEYS!
>>>>>>>>>>>>>>>>>>>>>>>>>>*<<<<<<<<<<<<<<<<<<<<<<<<<<


Unless you have the recovery password saved somewhere else, all currently encrypted files will be unrecoverable!
Are you sure you want to do this? (YES | no)> YES

Your recovery password for the new security key is: [your new recovery password]
Save this recovery password somewhere safe!  If you loose this password and run kryptr -i again, you will not be able to recover previously encrypted files!
$
```

You can run the init as many times as you want.  Just remember that you need to save the recovery password if you happen to reinitialize kryptr.

### Encrypt a File

To encrypt a file, you simply pipe in the file path, set the action flag to `encrypt`, and provide an output file path and name: `cat some-file.txt | kryptr -a=encrypt -o=some/directory/filename`

### Decrypt a File

To decrypt a file, you pipe in the file to be decrypted, set the action to `decrypt`, and provide the output file path and name: `cat some-encrpyted-file | kryptr -a=decrypt -o=some/directory/filename`

### Decrypt to Console Only

Sometimes you need to decrypt a file to get a value, or some information, but you don't want to save the decrypted text to a file.  To decrypt a file only to the console, simply omit the -o flag: `cat some-encrpyted-file | kryptr -a=decrypt`