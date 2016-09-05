# DIVT

Directory Integrity Verification Tool

GitHub: https://github.com/Remulak/DIVT

YouTube: https://youtu.be/FeZJY6LItKA

The DIVT program is used to verify the integrity of selected files in a directory.  I like having a command line tool, and many (most?) verification / hashing programs are gui based.  Ideally I want to compile this with py2exe to make a standalone tool since the systems I will be verifying typically don't have python installed (and I don't want to or can't install it on there)

I was inspired by a Windows tool that I have been using called FCIV, the File Checksum Integrity Verifier utility (https://support.microsoft.com/en-us/kb/841290).  FCIV is a great free Microsoft command line tool that can build a database of hashes.  This database can then be used for verification purposes.  While FCIV will tell you if a hash is wrong or a file missing, it cannot determine that new files were added to a directory.  DIVT is what I have wanted.  There's much more that can be added...

What it does:

+ Creates sqlite database of hashes that can be used for verification of a directory tree
+ Determines if files that match the extension you are interested in have changed (hash), have been deleted, or if new files with that extension have been added
+ Uses python standard libs so it should be OS agnostic (only tested on Windows)


Future ideas:

+ Speed / optimizing (putting everything into a sqlite database and using strings for keys is far from optimal... but it's usable now.  Possibly doing all in memory then writing the database once created...
+ Display filenames found with the same hash
+ Selectable hash function
+ Send hash values to VirusTotal
+ Tools to selectively edit the database instead of forcing a complete rebuild
+ Tools to add to the database after initial creation
+ Throw error codes
+ Lots of error checking
+ Deal with / skip open files

I'm sure there is much to be optimized - this is my first use of sqlite and first sizable python project.  The code needs some cleanup / compacting and make it look more pythonish.  Constructive criticism and improvement suggestions are greatly appreciated.

Thanks!

-Rod
