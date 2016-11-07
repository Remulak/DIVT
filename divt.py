# Directory Integrity Verification Tool (DIVT)
# Rod Rickenbach
# Intial: 9/4/16
# Revised: 11/6/16
# 
# DIVT is a tool designed to monitor directory content changes. 
# This includes changes to file hashes, files added and files deleted.
# Inspired by Microsoft's FCIV tool.

# Imports required:

# argparse is used to parse arguments passed on the command line
import argparse

# fnmatch supports unix style filename pattern matching.
# Used for -t command line switch
import fnmatch

# hashlib is used for hashing of files (md5/sha1/etc)
import hashlib

# sqlite database used for storing hashes and directory information
import sqlite3

# os is used to support file system access
import os

# exit used to halt execution and return appropriate error code to the user
from sys import exit


###############################################################################
# hashfile will perform a hash of a given filename using a hash function 
# contained in hashlib (md5, sha1, sha256, etc.). A buffer is used to break up
# large files, and is set to a default of 64k.  This can be tuned based on the
# expected filesizes to hash as well as them memory of the system.  This code 
# was initially based on code found here:
# http://stackoverflow.com/questions/22058048/hashing-a-file-in-python but has 
# evolved a bit... only the file reading while loop remains mostly unchanged.
###############################################################################

def hashfile(filename,hashtype,buffersize=65535):
    
    # point hashfn to the appropriate constructor method specified by hashtype
    try:
        hashfn = getattr(hashlib, hashtype)
    except AttributeError:
        print ('Hash function "{}" not found in hashlib!'.format(hashtype))
        exit(1)
    
    hash = hashfn()

    # Loop through to read the file in blocks of buffersize
    # This helps with hashing of large files vs reading all
    # into memory in one large block
    with open(filename, 'rb') as f:
        while True:
            data = f.read(buffersize)
            if not data:
                break
            hash.update(data)
    return(hash.hexdigest())


###############################################################################
# Update the Table containg hashes.  If the hash already exists, increment the 
# count associated with the hash.  This can help us find duplicate files
###############################################################################

def hash_file_and_store(filename,directory,hash_type,db_cursor):
    

    hash=hashfile(os.path.join(directory,filename),hash_type)

    add_file_to_database(filename,directory,hash,db_cursor)
    return

###############################################################################
# Update the Table containg hashes.  If the hash already exists, increment the 
# count associated with the hash.  This can help us find duplicate files
###############################################################################

def add_file_to_database(filename,directory,hash,db_cursor): 
    # See if the hash is already stored

    db_cursor.execute("SELECT * FROM hashes WHERE hash = ?",(hash,))               
    
    row = db_cursor.fetchone()
                    
    # if hash is found, increment the count, otherwise make initial entry
    if row:
        db_cursor.execute("UPDATE hashes SET count=? WHERE hash=? ",(row[1]+1,hash))
    else:
        db_cursor.execute("INSERT INTO hashes VALUES (?, ?)",(hash, 1))
                    
    # add file info to Files table
    db_cursor.execute("INSERT INTO files VALUES (?, ?, ?)",(filename,hash,directory))
    return


###############################################################################
# Create tables to store our needed information.
###############################################################################

def create_tables(db_cursor):
    # Creating a three (3) new SQLite tables for our use
    db_cursor.execute("CREATE TABLE directories(directory TEXT PRIMARY KEY, hash_algorithm TEXT, recursive INTEGER)")

    db_cursor.execute("CREATE TABLE types(type TEXT)")
        
    db_cursor.execute("CREATE TABLE hashes(hash TEXT PRIMARY KEY, count INT)")

    db_cursor.execute("CREATE TABLE files(filename TEXT, hash TEXT, parent TEXT)")
    return


###############################################################################
# Store the types of files we are interested in
###############################################################################

def store_types(filetypes,db_cursor):
    
    for ft in filetypes:
        db_cursor.execute("INSERT INTO types VALUES (?)",(ft,))

    return


###############################################################################
# Add files in directory to database
###############################################################################

def add_to_database(hash_type,file_types,directory_path,recursive,verification_database,force_overwrite=False):
    
    # If the database already exists, if so, only overwrite if force option set

    if os.path.isfile(verification_database):
        if force_overwrite:
            print ('Overwriting existing database "{}"'.format(verification_database))
            os.remove(verification_database)
        else:
            print ('Database file "{}" already exists'.format(verification_database))
            print ('Use \'-f\' option to force overwrite of database')
            return(1)
         
    # Create and connect to the database file
    con = sqlite3.connect(verification_database)
    cur = con.cursor()
    create_tables(cur)

    store_types(file_types,cur)

    # Initialize counter to summarize total number of hases
    hashcount=0

    # We are adding a directory to a database.  See if this should be done recursively...
    if recursive:
        # print("Recursive option enabled")
        # The code below is based on an example of recursive directory listing found at:
        # http://stackoverflow.com/questions/120656/directory-listing-in-python
        # Not sure if this comment is applicable as the code has been massaged a bit
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(directory_path)):
        
            # insert the base directory as first entry to the directories table

            cur.execute("INSERT INTO directories VALUES (?, ?, ?)",(dirpath,hash_type,True))
      
            for filename in filenames:
                
                for type in file_types:
                    if fnmatch.fnmatch(filename, type):
                        
                        hashcount=hashcount+1
                    
                        hash_file_and_store(filename,dirpath,hash_type,cur)

    # Otherwise not recursive.  
    else:
        
        dirpath = os.path.abspath(directory_path)
        
        cur.execute("INSERT INTO directories VALUES (?, ?, ?)",(dirpath,hash_type,False))

        filenames = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath,f))]

        for filename in filenames:
            for type in file_types:
        
                if fnmatch.fnmatch(filename, type):
                    
                    hashcount=hashcount+1
                    
                    hash_file_and_store(filename,dirpath,hash_type,cur)

    # Commit changes and close connection to the database file
    con.commit()
    con.close()
    
    # Print some useful statistics and return showing no errors
    print ('\nAdded {0} files to the hash database "{1}"'.format(hashcount,verification_database))
    return(0)


###############################################################################
# Update database with new information
###############################################################################

def update_database(verification_database, files_dict):
    
    # If the database already exists, if so, only overwrite if force option set

    if not os.path.isfile(verification_database):
        print ('Database "{}" not accessable.'.format(verification_database))
        return(1)
                 
    # Connect to the database file
    con = sqlite3.connect(verification_database)
    cur = con.cursor()
    
    # Initialize some counters
    updated=0
    added=0
    removed=0

    # Loop through and process all files that don't match existing:
    for key in files_dict:
        status = files_dict[key][0]
        if status!='Found':
            # Split full filename into file and directory
            directory=os.path.dirname(key)
            file_name=os.path.basename(key)

            if status=='Mismatch':
                updated+=1;
                old_hash=files_dict[key][1]
                new_hash=files_dict[key][2]
                update_hash_in_database(file_name,directory,old_hash,new_hash,cur)
            
            elif status=='New':
                added+=1
                new_hash=files_dict[key][1]
                add_file_to_database(file_name,directory,new_hash,cur)
            
            elif status=='Missing':
                removed+=1
                old_hash=files_dict[key][1]
                remove_file_from_database(file_name,directory,old_hash,cur)
        
    con.commit()
    con.close()
    
    if updated+added+removed:
        print ('Database Update Status:')
        print ('{} signatures added'.format(added))
        print ('{} signatures updated'.format(updated))
        print ('{} signatures removed'.format(removed))

    else:
        print ('Database already up to date')

    return(0)


###############################################################################
# Update existing hash in database.  Fix hash count as well
###############################################################################

def update_hash_in_database(file_name,directory,old_hash,new_hash,db_cursor):


    # Update Hash based on filename and parent directory (unique pair)
    db_cursor.execute("UPDATE files SET hash=? WHERE filename=? AND parent=?",(new_hash,file_name,directory))
    decrement_hash_count(old_hash,db_cursor)
    return


##############################################################################
# Remove file Update the Table containg hashes.  If the hash already exists, increment the 
# count associated with the hash.  This can help us find duplicate files
###############################################################################

def remove_file_from_database(file_name,directory,hash_value,db_cursor):
    
    db_cursor.execute("DELETE FROM files WHERE hash=? AND filename=? AND parent=?",(hash_value,file_name,directory))
    decrement_hash_count(hash_value,db_cursor)
    return


###############################################################################
# Decrement hash count in Hashes table, delete if decrementing <=0
###############################################################################   

def decrement_hash_count(hash_value,db_cursor):

    # Fix (decrement) the hash count in Hashes table
    db_cursor.execute("SELECT * FROM hashes WHERE hash = ?",(hash_value,))
    row = db_cursor.fetchone() 

    # if hash is found, decrement the count if >1 , otherwise delete entry
    if row:
        if row[1] > 1:
            db_cursor.execute("UPDATE hashes SET count=? WHERE hash=?",(row[1]-1,hash_value))
        else:
            db_cursor.execute("DELETE FROM hashes WHERE hash=?",(hash_value,))
                    
    return


###############################################################################
# Verify files we are looking for are in the database.  Stores results in
# the dictionary 'files_dict'.  This contains information on matched files,
# files not found in the database but should be, new files, files with 
# mishmatched hashes, as well as missing files
###############################################################################
def verify_files(filenames,dirpath,filetypes,files_dict,hash_type):
    
    for filename in filenames:
        
        full_filename = os.path.join(dirpath,filename)
        
        for filetype in filetypes:
            
            # Only check files of the 'type' we care about
            if fnmatch.fnmatch(filename, filetype):

                # get hash
                current_hash = hashfile(full_filename,hash_type)

                # Look for filename in the dictionary of files
                if full_filename in files_dict:
                    
                    original_hash = files_dict[full_filename][1]

                    # Tag according to whether the hash matches or not
                    if current_hash == original_hash:
                        files_dict[full_filename][0]=['Found',original_hash]
                    else:
                        files_dict[full_filename]=['Mismatch',original_hash,current_hash]
            
                # Otherwise, file not found, aka new, so mark appropriately
                else:
                    files_dict[full_filename]=['New',current_hash]

    return


###############################################################################
# Verify the contents of the verification database
###############################################################################

def verify_against_database(verification_database,files_dict):

    #Check to ensure db exists
    if os.path.isfile(verification_database):
        con = sqlite3.connect(verification_database)
        cur = con.cursor()
    else:
        # Error
        print ('Database file "{}"" does not exist!'.format(verification_database))
        return(1)

    # Grab the list of types that we used to select files to be stored in the db

    cur.execute("SELECT type FROM types")   
    
    stored_types = [tup[0] for tup in cur.fetchall()]

    # Determine if this is a recursive search
    cur.execute("SELECT * from directories")
    
    # Stored recusrsion flag: 1 = recursion, 0 = no recursion
    # This value is stored for every directory entry now, so we just grab the first one
    # Note, if there is no recursion, then there will be only one directory entry... Think about it. ;)
    # This may (and probably will) change in future versions...
    row=cur.fetchone()
    hash_type=row[1]
    recursion = row[2]

    # Determine if this is a recursive search
    cur.execute("SELECT recursive from directories")
    
    # Stored recusrsion flag: 1 = recursion, 0 = no recursion
    # This value is stored for every directory entry now, so we just grab the first one
    # Note, if there is no recursion, then there will be only one directory entry... Think about it. ;)
    # This may (and probably will) change in future versions...
    recursion = cur.fetchone()[0]
    
    # Get a list of all the directories that we examined
    cur.execute("SELECT (directory) FROM directories")   
    
    stored_parent_directories = [tup[0] for tup in cur.fetchall()]
    
    # Again, the way this program works currently, it is either recursive or not. Either way, since we can only
    # add one directory, we only need the original root path... for now.  This will probably change in future versions.
    stored_root_directory = stored_parent_directories[0]

    # Create a dictionary of stored filenames (with full path) and associated hash
    # Also set a flag to see if we have rehashed this file
    cur.execute("SELECT * FROM files")   
    
    rows = cur.fetchall()
    
    # Done reading from the db
    con.close() 

    # Loop through the read data
    for row in rows:

        # Parse each row for the filename, hash, and directory  
        stored_filename = row[0]
        stored_hash = row[1]
        stored_directory = row[2]
        
        # Construct the full filename
        full_stored_name = os.path.join(stored_directory,stored_filename)

        # Initially, mark all files in the database as missing
        files_dict[full_stored_name]=['Missing',stored_hash]


    if recursion:

        for dirpath, dirnames, filenames in os.walk(stored_root_directory):
            verify_files(filenames,dirpath,stored_types,files_dict,hash_type)           

    # Otherwise not recursive.  
    else:

        dirpath = stored_root_directory

        filenames = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath,f))]

        verify_files(filenames,dirpath,stored_types,files_dict,hash_type)

    return(0)
    

###############################################################################
# Display verification results
###############################################################################

def display_verification_results(files_dict):
    
    print ('\n\nVerification results:')
    print ('---------------------\n')
    
    problems_found=0

    # Print out hash mismatches 
    for key in files_dict:
        if files_dict[key][0]=='Mismatch':
            problems_found+=1
            print ('Hash mismatch: {}'.format(key))
            print ('\t Stored Hash:  {}'.format(files_dict[key][1]))
            print ('\t Current Hash: {}\n\n'.format(files_dict[key][2]))

    # Print out files not found
    for key in files_dict:
        if files_dict[key][0]=='Missing':
            problems_found+=1
            print ('File not found: {}\n\n'.format(key))
    
    # Print out files not in the database 
    for key in files_dict:
        if files_dict[key][0]=='New':
            problems_found+=1
            print ('New file found: {}'.format(key))
            print ('\t Hash value: {}\n\n'.format(files_dict[key][1]))

    print ('{} files hashed\n'.format(len(files_dict)))

    if problems_found:
        print ('{} problems found.\n\n'.format(problems_found))
        return(1)
    else:
        print ('No problems found.\n\n')
        return(0)


###############################################################################
# MAIN PROGRAM
###############################################################################

def main():
    # Set up the arguments using argparse
    parser = argparse.ArgumentParser(description='Verify contents of a directory')
    parser.add_argument('-d', '--dir', help='directory to add')
    parser.add_argument('-ht', '--hashtype', help='hashing algorithm to use (defaults to SHA1)')
    parser.add_argument('-f', '--force', action='store_true', help='force an overwrite of an existing database')
    parser.add_argument('-t', '--type', action='append', help='filename types to add')
    parser.add_argument('-r', '--recursive', action='store_true', help = 'turn on recursive adding of directories')
    parser.add_argument('-u', '--update', action='store_true', help = 'update database to include changes to directories and hashes')
    parser.add_argument('database', help='name of hash database to use')
    
    args = parser.parse_args()
    
    # If no args type specified, default to wildcard (*)
    if args.type == None:
        args.type = ['*']
        
    # If no hash algorithm is specified, default to sha1
    if args.hashtype == None:
        hashtype = 'sha1'
    else:
        hashtype=args.hashtype.lower()

    # Define and clear out the error value that main will exit with
    error_val = 0

    # Check to see if we are adding directories to a database
    if args.dir:
        error_val=add_to_database(hashtype,args.type,args.dir,args.recursive,args.database,args.force)

    # If we are not adding files, we are verifying or updating database
    else:
        # Create empty dictionary to hold all files and associated info we find
        files_dict = {}
        # Call verification function which puts all info we find from the 
        # verification process into files_dict
        error_val=verify_against_database(args.database, files_dict)
        if error_val:
            exit(error_val)
        else:
            if args.update:
                error_val=update_database(args.database, files_dict)
            else:
                error_val=display_verification_results(files_dict)

    exit(error_val)

###############################################################################
# Call main program if run directly, ie not run as a module
###############################################################################

if __name__ == '__main__':
    main()