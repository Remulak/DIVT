# Directory Integrity Verification Tool (DIVT)
# Rod Rickenbach
# 9/4/16
#
# The idea behind this tool is to monitor a directory for changes.  This includes changes to file hashes, files added
# and files deleted.

import argparse
import fnmatch
import hashlib
import sqlite3
import os
from sys import exit


# hashfile will perform a hash of a given filename using a hash function contained in hashlib (md5, sha1, sha256, etc.).
# A buffer is used to break up large files, and is set to a default of 64k.  This can be tuned based on the expected
# filesizes to hash as well as them memory of the system.  This code was initially based on code found here:
# http://stackoverflow.com/questions/22058048/hashing-a-file-in-python but has evolved a bit... only the file reading while
# loop remains mostly unchanged.

def hashfile(filename,hashtype,buffersize=65535):
    
    # point hashfn to the appropriate constructor method specified by hashtype
    try:
        hashfn = getattr(hashlib, hashtype)
    except AttributeError:
        print 'Hash function "%s" not found in hashlib!' % (hashtype)
        exit()
    
    hash = hashfn()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(buffersize)
            if not data:
                break
            hash.update(data)
    return(hash.hexdigest())

# Update the Table containg hashes.  If the hash already exists, increment the count associated with the hash.  This can
# Help us find duplicate files

def store_file_and_hash(filename,directory):
    
    hash=hashfile(os.path.join(directory,filename),'sha1')
    
    # See if the hash is already stored

    cur.execute("SELECT * FROM Hashes WHERE Hash = ?",(hash,))               
    
    row = cur.fetchone()
                    
    # if hash is found, increment the count, otherwise make initial entry
    if row:
        cur.execute("UPDATE Hashes SET Count=? WHERE Hash=?",(row[1]+1,hash))
    else:
        cur.execute("INSERT INTO Hashes VALUES (?, ?)",(hash, 1))
                    
    # add file info to Files table
    cur.execute("INSERT INTO Files VALUES (?, ?, ?)",(filename,hash,directory))
    return

# Create tables to store our needed information.

def create_tables():
    # Creating a three (3) new SQLite tables for our use
    cur.execute("CREATE TABLE Directories(Directory TEXT PRIMARY KEY, Recursive INTEGER)")

    cur.execute("CREATE TABLE Types(Type TEXT)")
        
    cur.execute("CREATE TABLE Hashes(Hash TEXT PRIMARY KEY, Count INT)")

    cur.execute("CREATE TABLE Files(Filename TEXT, Hash TEXT, Parent TEXT)")
    return

# Store the types of files we are interested in
def store_types(filetypes):
    
    for ft in filetypes:
        cur.execute("INSERT INTO Types VALUES (?)",(ft,))

    return


# The meat of the program

# Set up the arguments using argparse
parser = argparse.ArgumentParser(description='Verify contents of a directory')
parser.add_argument('-d', '--dir', help='directory to add')
parser.add_argument('-t', '--type', help='filename types to add', action='append')
parser.add_argument('-r', '--recursive', help = 'recursively add directories',action='store_true')
parser.add_argument('database', help='name of hash database to use')
args = parser.parse_args()

if args.type == None:
    args.type = ['*']
    
if args.dir:

    # If the database already exists, err on the side of caution and exit, otherwise create a new db.
    if os.path.isfile(args.database):
        print 'Database file "%s" already exists'% (args.database)
        exit()
    else:
        # Create and connect to the database file
        con = sqlite3.connect(args.database)
        cur = con.cursor()
        create_tables()

        store_types(args.type)


    # Initialize counter to summarize total number of hases
    hashcount=0

    # We are adding a directory to a database.  See if this should be done recursively...
    if args.recursive:
        # print("Recursive option enabled")
        # The code below is based on an example of recursive directory listing found at:
        # http://stackoverflow.com/questions/120656/directory-listing-in-python
        # Not sure if this comment is applicable as the code has been massaged a bit
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(args.dir)):
        
            # insert the base directory as first entry to the directories table

            cur.execute("INSERT INTO Directories VALUES (?, ?)",(dirpath,True))

           
            for filename in filenames:
                
                for type in args.type:
                    if fnmatch.fnmatch(filename, type):
                        
                        hashcount=hashcount+1
                    
                        store_file_and_hash(filename,dirpath)


    # Otherwise not recursive.  
    else:
        
        dirpath = os.path.abspath(args.dir)
        
        cur.execute("INSERT INTO Directories VALUES (?, ?)",(dirpath,False))

        filenames = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath,f))]

        for filename in filenames:
            for type in args.type:
        
                if fnmatch.fnmatch(filename, type):
                    
                    hashcount=hashcount+1
                    
                    store_file_and_hash(filename,dirpath)


    # Commit changes and close connection to the database file
    con.commit()
    con.close()
    
    # Exit with some useful info
    print '\nAdded {0} files to the hash database "{1}"'.format(hashcount,args.database)
    exit()

# Otherwise we are verifying a database, not adding
else:
    total_files_hashed=0

    #Check to ensure db exists
    if os.path.isfile(args.database):
        con = sqlite3.connect(args.database)
        cur = con.cursor()
    else:
        # Error
        print 'Database file "%s" does not exist!'% (args.database)
        exit()


    # Grab the list of types that we used to select files to be stored in the db

    cur.execute("SELECT Type FROM Types")   
    
    stored_types = [tup[0] for tup in cur.fetchall()]


    # Determine if this is a recursive search
    cur.execute("SELECT Recursive from Directories")
    
    # Stored recusrsion flag: 1 = recursion, 0 = no recursion
    # This value is stored for every directory entry now, so we just grab the first one
    # Note, if there is no recursion, then there will be only one directory entry... Think about it. ;)
    # This may (and probably will) change in future versions...
    stored_recursion = cur.fetchone()[0]
    

    # Get a list of all the directories that we examined
    cur.execute("SELECT (Directory) FROM Directories")   
    
    stored_parent_directories = [tup[0] for tup in cur.fetchall()]
    
    # Again, the way this program works currently, it is either recursive or not. Either way, since we can only
    # add one directory, we only need the original root path... for now.  This will probably change in future versions.
    stored_root_directory = stored_parent_directories[0]


    # Create a dictionary of stored filenames (with full path) and associated hash
    # Also set a flag to see if we have rehashed this file
    cur.execute("SELECT * FROM Files")   
    
    rows = cur.fetchall()
    
    # Done reading from the db
    con.close() 

    # Three dictionaries, one for the files we have stored in the db, another for new files we find now
    # and one for hash mismatches
    stored_files_dict = {}
    new_files_dict = {}
    hash_mismatch_dict = {}

    for row in rows:

        stored_filename = row[0]
        stored_hash = row[1]
        stored_directory = row[2]
        
        full_stored_name = os.path.join(stored_directory,stored_filename)

        stored_files_dict[full_stored_name]=[stored_hash,'Lost']


    if stored_recursion:

        for dirpath, dirnames, filenames in os.walk(stored_root_directory):
                 
            for filename in filenames:
                
                full_filename = os.path.join(dirpath,filename)
                
                for filetypes in stored_types:
                    
                    if fnmatch.fnmatch(filename, filetypes):

                        hash = hashfile(full_filename,'sha1')

                        total_files_hashed +=1

                        if full_filename in stored_files_dict:
                            
                            stored_files_dict[full_filename][1]='Found'
                            
                            if hash != stored_files_dict[full_filename][0]:
                                hash_mismatch_dict[full_filename]=(stored_files_dict[full_filename][0],hash)
                    
                        else:
                            new_files_dict[full_filename]=hash


    # Otherwise not recursive.  
    else:

        dirpath = stored_root_directory

        filenames = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath,f))]
        print filenames


        for filename in filenames:
            full_filename = os.path.join(dirpath,filename)
            
            for filetype in stored_types:
        
                if fnmatch.fnmatch(filename, filetype):

                    hash = hashfile(full_filename,'sha1')

                    total_files_hashed +=1

                    if full_filename in stored_files_dict:
                            
                        stored_files_dict[full_filename][1]='Found'
                            
                        if hash != stored_files_dict[full_filename][0]:
                            hash_mismatch_dict[full_filename]=(stored_files_dict[full_filename][0],hash)
                    
                    else:
                        new_files_dict[full_filename]=hash


    print'\n\nVerification results:'
    print'---------------------\n'
    
    problems_found=0

    # Print out hash mismatches 
    for key in hash_mismatch_dict:
        problems_found+=1
        print 'Hash mismatch: {}'.format(key)
        print '\t Stored Hash:  {}'.format(hash_mismatch_dict[key][0])
        print '\t Current Hash: {}\n\n'.format(hash_mismatch_dict[key][1])

    # Print out files not found
    for key in stored_files_dict:
        for value in stored_files_dict[key]:
            if 'Lost' in value:
                problems_found+=1
                print 'File not found: {}\n\n'.format(key)
    
    # Print out files not in the database 
    for key in new_files_dict:
        problems_found+=1
        print 'New file found: {}'.format(key)
        print '\t Hash value: {}\n\n'.format(new_files_dict[key])

    print'{} files hashed\n'.format(total_files_hashed)

    if problems_found:
        print('{} problems found.\n\n').format(problems_found)
    else:
        print('No problems found.\n\n')