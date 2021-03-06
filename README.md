# DIVT

Directory Integrity Verification Tool

GitHub: https://github.com/Remulak/DIVT

YouTube (original): https://youtu.be/FeZJY6LItKA
YouTube (latest): https://youtu.be/BxcekLjWN6Y

The DIVT program is used to verify the integrity of selected files in a directory.  I like having a command line tool, and many (most?) verification / hashing programs are gui based.  Ideally I want to use a compiled version to make a standalone tool since the systems I will be verifying typically don't have python installed (and I don't want to or can't install it on there).  I successfully used PyInstaller to make the executable for windows.  Other programs that can make stand alone packages are cx_Freeze, py2exe, and py2app (Mac OS X only)

I was inspired by a Windows tool that I have been using called FCIV, the File Checksum Integrity Verifier utility (https://support.microsoft.com/en-us/kb/841290).  FCIV is a great free Microsoft command line tool that can build a database of hashes.  This database can then be used for verification purposes.  While FCIV will tell you if a hash is wrong or a file missing, it cannot determine that new files were added to a directory.  DIVT is what I have wanted.  There's much more that can be added...

##What it does:

+ Creates sqlite database of hashes that can be used for verification of a directory tree
+ Determines if files that match the extension you are interested in have changed (hash), have been deleted, or if new files with that extension have been added
+ Uses python standard libs so it should be OS agnostic (only tested on Windows)

##Usage:

usage: divt no VT api Key.py [-h] [-d DIRECTORY] [-ht HASHTYPE] [-f] [-t TYPE]
                             [-exe] [-r] [-u] [-vt] [-st] [-dup] [-lbp]
                             [-sbp SUBSTITUTEBASEPATH] [-l] [-lh] [-lc]
                             database


Verify contents of a directory


positional arguments:

  database              name of hash database to use


optional arguments:

  -h, --help            show this help message and exit
  
  -d DIRECTORY, --directory DIRECTORY
                        directory to add
                        
  -ht HASHTYPE, --hashtype HASHTYPE
                        hashing algorithm to use (defaults to SHA1)
                        
  -f, --force           force an overwrite of an existing database
  
  -t TYPE, --type TYPE  filename types to add
  
  -exe, --executables   Select executable files (Mac OS or Windows only)
  
  -r, --recursive       turn on recursive adding of directories
  
  -u, --update          update database to include changes to directories and 
                        hashes
                        
  -vt, --virustotal     run new file hashes and hash mismatches through Virus
                        Total
                        
  -st, --signtool       Check windows verification signature chain
  
  -dup, --duplicates    List all files with duplicate hashes in the database
  
  -lbp, --listbasepath  Display the base path of the database entries
  
  -sbp SUBSTITUTEBASEPATH, --substitutebasepath SUBSTITUTEBASEPATH
                        New base path to use for verification
                        
  -l, --list            List all contents of the database
  
  -lh, --listhashes     List all file hashes in the database
  
  -lc, --listcerts      List all signtool generated certificate chains in the
                        database
                        

##Latest improvements:
* -exe option automatically selects executable file extensions on Windows and Mac OS
* -st option uses signtool on Microsoft Windows to add certificate chains to the database
* -vt option will send the hash of new files or files with hash or certicificate changes to Virus Total to see if it is in their database
* -dup lists all files with duplicate hashes in the database
* -lbp lists the base path used for the database (root directory used to create the database)
* -sbp allows you to subsititute a new base path for that listed by -lbp
* list the database contents by hash values, certificates, or all


##Future ideas:

+ Speed / optimizing (putting everything into a sqlite database and using strings for keys is far from optimal... but it's usable now.  Possibly doing all in memory then writing the database once created...
+ More tools to selectively edit or add to the database
+ Add a flag to a file/directory to skip checking?
+ Lots more error checking
+ Deal with / skip open files

Constructive criticism and improvement suggestions are greatly appreciated.

Thanks!
