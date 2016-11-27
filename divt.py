# Directory Integrity Verification Tool (DIVT)
# Rod Rickenbach
# Intial: 9/4/16
# Revised: 11/7/16
# Revised: 11/26/16
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

# os is used to support file system access
import os

# required to perform HTTPS request to VirusTotal API interface
import requests

# sqlite database used for storing hashes and directory information
import sqlite3

# subprocess is used to call Microsoft's signtool.exe
import subprocess

# time used for sleep function
from time import sleep as _sleep

# exit used to halt execution and return appropriate error code to the user
from sys import exit as _exit

# platform used to determine if we are on a Mac OS
from sys import platform as _platform

# used to determine if we are running as Administrator in Windows which
# is necessary for signtool
import ctypes


###############################################################################
# print_vt_hash_check will check to see if a MD5/SHA1/SHA256 hash is in the 
# VirusTotal database.  The code below is mostly from the VirusTotal API
# guide at:
# https://www.virustotal.com/en/documentation/public-api/#getting-file-scans
# and was influenced by Gerry Auger's SuspectDomainDetector.py at:
# https://github.com/gerryguy311/CSC842/tree/master/Module5
#
# Checks return a JSON formatted response that indicates whether the file 
# hash has been processed by VT, and if so the AV responses to the file
#
# NB: This only checks hashes in the Virus Total database.  If the file hash
# is not found, it is not uploaded for scanning.  Why?  Virus Total says:
# "Keep in mind that files sent using the API have the lowest scanning 
# priority, depending on VirusTotal's load, it may take several hours before 
# the file is scanned, so query the report at regular intervals until the 
# result shows up and do not keep sending the file repeatedly"
#
# So the best course of action would be to manually upload a file and see
# the results.
###############################################################################

def print_VT_hash_check(hash_type, hash_value):

    ###########################################################################
    # Virus Total API variables:
    ###########################################################################
    # VIRUS TOTAL queries:
    # Enter an API key for Virus Total below if you want to use the service to 
    # optionally examine hash mismatches

    VT_API_key = 'd21730e33b1896f4c4a0c13ae03c3b403900ef27df518b509901fc2752655020'

    # Time (in seconds) to sleep between queries.  For public API keys, this can
    # be no less than 15 seconds.  The public API actually 4 queries per minute, 
    # so we average this out to one every 15 seconds.  We could batch together 4 
    # requests at a time for hash checking, but this would be more complicated 
    # to program and would have "bursty" output once per minute...  

    VT_sleep = 15 

    ###########################################################################
    
    # Virus Total only accepts MD5/SHA1/SHA256 hashes at this time.  Act
    # appropriately...

    if not (hash_type == 'md5' or hash_type == 'sha1' or hash_type == 'sha256'):
        print ('\tVirus Total cannot check hash type {}\n'.format(hash_type))
        return

    print ('  Checking hash at Virus Total:')
    # Check to see if this function has been called before, if so, sleep
    if print_VT_hash_check.has_been_called:
        _sleep(VT_sleep)
    else:
        print_VT_hash_check.has_been_called = True

    params = {'apikey': VT_API_key, 'resource': hash_type}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)

    try:
        json_VT_response = response.json()
        VT_response_code = json_VT_response['response_code']
        VT_positives = json_VT_response['positives']
        VT_total = json_VT_response['total']
        VT_link = json_VT_response['permalink']
        VT_percentage = (float(VT_positives)/float(VT_total))
        if VT_response_code == 1:
            print ('    Virus Total Score: {0:.0%} ({1} of {2} positive)'.format(
                VT_percentage,VT_positives,VT_total))
            print ('    More info: {}\n'.format(VT_link))
        else:
            print ('    File not uploaded or scanned by Virus Total yet.\n')

    except:
        if response.status_code==200:
            print ('    File not uploaded or scanned by Virus Total yet.\n')
        else: 
            print ('    ERROR {} response from VirusTotal for hash: {}\n'.format(
                response.status_code,hash_value))


###############################################################################
# call_signtool uses Microsoft's Signtool.exe to check signatures of files
###############################################################################
def call_signtool(full_filename):

    # Location of signtool.exe file

    signtool = 'C:\Program Files\Microsoft SDKs\Windows\\v6.1\Bin\signtool.exe'
  
    # If signtool is successful, store the output of the command in output
    try:
        output = subprocess.check_output([signtool, 'verify', '/pa', '/v', full_filename],
            stderr=subprocess.STDOUT, shell=False)
        output=strip_signtool_output(output)
        return(output)


    # If signtool gives an error, there is no signature for the file  
    except subprocess.CalledProcessError:
        return('NO SIGNATURE')


###############################################################################
# Strip down the signtool output to just the toolchain.  Need to do this in
# case we change the basepath
###############################################################################

def strip_signtool_output(output_string):

    lines=output_string.splitlines(True)
    stripped_output=''.join(lines[4:-9])
    return(stripped_output)


###############################################################################
# windows_os returns true if we are in a Windows environment
###############################################################################

def windows_os():
    
    if os.name == 'nt':
        return True
    else:
        return False


###############################################################################
# mac_os returns true if we are in an Apple Mac environment
###############################################################################

def mac_os():
    
    if _platform() == 'darwin':
        return True
    else:
        return False


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
        _exit(1)
    
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
# Create file hashes.  Also grab signtool info if appropriate
###############################################################################

def hash_file_and_store(filename,directory,hash_type,use_signtool,db_cursor):
    
    full_filename=os.path.join(directory,filename)

    file_hash=hashfile(full_filename,hash_type)

    if use_signtool:
        # get output 
        signtool_output = call_signtool(full_filename)
    
        # Create a hash of the output string
        if signtool_output != 'NO SIGNATURE':
            signtool_output_hash = hashlib.sha1(signtool_output).hexdigest()
        else:
            signtool_output_hash = 'NO SIGNATURE'
    # if signtool is not used, use N/A for database verification (ie don't
    # use signtool if we see an N/A)
    else:
        signtool_output='N/A'
        signtool_output_hash='N/A'
    
    add_file_to_database(filename,directory,file_hash,
        signtool_output_hash,signtool_output,db_cursor)

    return


###############################################################################
# Update the Table containg hashes.  If the hash already exists, increment the 
# count associated with the hash.  This can help us find duplicate files
###############################################################################

def add_file_to_database(filename,directory,file_hash,signtool_output_hash,
                        signtool_output,db_cursor): 
    # See if the hash is already stored

    db_cursor.execute("SELECT * FROM hashes WHERE hash = ?",(file_hash,))               
    
    row = db_cursor.fetchone()
                    
    # if hash is found, increment the count, otherwise make initial entry
    if row:
        db_cursor.execute("UPDATE hashes SET count=? WHERE hash=? ",(row[1]+1,file_hash))
    else:
        db_cursor.execute("INSERT INTO hashes VALUES (?, ?)",(file_hash, 1))
                    
    # add file info to Files table, default to N/A for signtool values
    db_cursor.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?)",
                (filename,file_hash,directory,signtool_output_hash,
                signtool_output))
    return

###############################################################################
# Create tables to store our needed information.
###############################################################################

def create_tables(db_cursor):
    # Creating a three (3) new SQLite tables for our use
    db_cursor.execute("CREATE TABLE directories(directory TEXT PRIMARY KEY,\
                        hash_algorithm TEXT, recursive INTEGER, signtool INTEGER)")

    db_cursor.execute("CREATE TABLE types(type TEXT)")
        
    db_cursor.execute("CREATE TABLE hashes(hash TEXT PRIMARY KEY, count INT)")

    db_cursor.execute("CREATE TABLE files(filename TEXT, hash TEXT, parent TEXT,\
                        signtool_output_hash TEXT, signtool_output TEXT)")
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

def add_to_database(hash_type,file_types,directory_path,recursive,
                    verification_database,use_signtool,force_overwrite=False):
    
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

            cur.execute("INSERT INTO directories VALUES (?, ?, ?, ?)",(dirpath,hash_type,True,use_signtool))
      
            for filename in filenames:
                
                for type in file_types:
                    if fnmatch.fnmatch(filename, type):
                        
                        hashcount=hashcount+1
                    
                        hash_file_and_store(filename,dirpath,hash_type,use_signtool,cur)

    # Otherwise not recursive.  
    else:
        
        dirpath = os.path.abspath(directory_path)
        
        cur.execute("INSERT INTO directories VALUES (?, ?, ?, ?)",(dirpath,hash_type,False,use_signtool))

        filenames = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath,f))]

        for filename in filenames:
            for type in file_types:
        
                if fnmatch.fnmatch(filename, type):
                    
                    hashcount=hashcount+1
                    
                    hash_file_and_store(filename,dirpath,hash_type,use_signtool,cur)

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
                old_hash=files_dict[key][2]
                new_hash=files_dict[key][3]
                new_signtool_output_hash=files_dict[key][5]
                new_signtool_output=files_dict[key][7]
                update_hash_in_database(file_name,directory,old_hash,new_hash,cur)
            
            elif status=='New':
                added+=1
                hash_type=files_dict[key][1]
                use_signtool=files_dict[key][3]
                hash_file_and_store(file_name,directory,hash_type,use_signtool,cur)
            
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

def update_hash_in_database(file_name,directory,old_hash,new_hash,
                    new_signtool_output_hash,new_signtool_output,db_cursor):


    # Update Hash based on filename and parent directory (unique pair)
    db_cursor.execute("UPDATE files SET hash=?,signtool_output_hash=?,\
    signtool_output=? WHERE filename=? AND parent=?",(new_hash,
        new_signtool_output_hash,new_signtool_outputfile_name,directory))
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
def verify_files(filenames,dirpath,filetypes,files_dict,hash_type,use_signtool):
    
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
                    original_signtool_output_hash = files_dict[full_filename][2]
                    original_signtool_output = files_dict[full_filename][3]

                    # Generate new signtool output and associated hash if applicable 
                    if original_signtool_output == 'N/A':
                        signtool_output='N/A'
                        signtool_output_hash='N/A'
                        
                    else:
                        signtool_output=call_signtool(full_filename)
                        
                        if signtool_output == 'NO SIGNATURE':
                            signtool_output_hash = 'NO SIGNATURE'
                        else:
                            signtool_output_hash=hashlib.sha1(signtool_output).hexdigest()

                    # We know the file is here.  Keep it as 'Missing' for now so we can
                    # populate the rest of the fields.  This first status field will
                    # be changed below
                    files_dict[full_filename]=['Missing',hash_type,original_hash,
                            current_hash,original_signtool_output_hash,
                            signtool_output_hash,original_signtool_output,signtool_output]
                    
                    # Tag according to whether the hash matches or not
                    if current_hash == original_hash:
                        files_dict[full_filename][0]='Found'
                    else:
                        files_dict[full_filename][0]='Mismatch'

                    # Unclear if a signtool mismatch can occur if a hash
                    # mismatch does not.
                    if signtool_output!=original_signtool_output:
                        files_dict[full_filename][0]=='Mismatch'

                # Otherwise, file not found, aka new, so mark appropriately
                else:
                    files_dict[full_filename]=['New',hash_type,current_hash,use_signtool]

    return


###############################################################################
# Verify the contents of the verification database
###############################################################################

def verify_against_database(verification_database,new_basepath,files_dict):

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

    # Determine the hash algorithm used
    cur.execute("SELECT * from directories")
    
    # This value is stored for every directory entry now, so we just grab the first one as all
    # must be the same

    row = cur.fetchone()

    # get the root directory, aka basepath
    basepath = row[0]

    # setup the root_path ie working base path
    if new_basepath:
        root_path=new_basepath
    else:
        root_path=basepath


    # Get the hash type
    hash_type = row[1]

    # Determine if this is a recursive search
    # Stored recusrsion flag: 1 = recursion, 0 = no recursion
    # This value is stored for every directory entry now, so we just grab the first one
    # Note, if there is no recursion, then there will be only one directory entry... Think about it. ;)
    # This may (and probably will) change in future versions...
    recursion = row[2]

    # Determine if the database uses signtool verification 1=yes, 0=no
    use_signtool = row[3]
    
    # Create a dictionary of stored filenames (with full path) and associated hash
    # Also set a flag to see if we have rehashed this file
    cur.execute("SELECT * FROM files")   
    
    rows = cur.fetchall()
    
    # Done reading from the db
    con.close() 

    # Loop through the read data
    for row in rows:

        # Parse each row for the filename, hash, and directory  
        file_name = row[0]
        hash_value = row[1]
        directory = row[2]
        signtool_output_hash = row[3]
        signtool_output = row[4]

        # Change the basepath if desired
        if new_basepath:
            directory=directory.replace(basepath,new_basepath)

        # Construct the full filename
        full_file_name = os.path.join(directory,file_name)

        # Initially, mark all files in the database as missing
        files_dict[full_file_name]=['Missing',hash_value,signtool_output_hash,
                                        signtool_output]

    if recursion:

        for dirpath, dirnames, filenames in os.walk(root_path):
            verify_files(filenames,dirpath,stored_types,files_dict,hash_type,use_signtool)           

    # Otherwise not recursive.  
    else:

        try:
            filenames = [f for f in os.listdir(root_path) if os.path.isfile(os.path.join(root_path,f))]
        except:
            print('\nERROR:Problem accessing {}'.format(root_path))
            return(1)

        verify_files(filenames,root_path,stored_types,files_dict,hash_type,use_signtool)

    return(0)
   

###############################################################################
# List files with duplicate hashes in the verification database
###############################################################################

def list_duplicates(verification_database):

    #Check to ensure db exists
    if os.path.isfile(verification_database):
        con = sqlite3.connect(verification_database)
        cur = con.cursor()
    else:
        # Error
        print ('Database file "{}"" does not exist!'.format(verification_database))
        return(1)

    # Select all hash info where the count > 1
    cur.execute("SELECT * FROM hashes WHERE count > 1")
    
    hash_rows = cur.fetchall()
    
    # if no rows, no duplicates found
    if len(hash_rows) == 0:
        print ('No duplicate hashes found.\n')
        con.close() 
        return(0)    
    
    # Loop through the read data
    for hash_row in hash_rows:

        # Parse each hash_row for the hash and number of duplicates 
        stored_hash = hash_row[0]
        stored_count = hash_row[1]

        print ('{}:'.format(stored_hash))
        
        cur.execute("SELECT * FROM files WHERE hash = ?",(stored_hash,))

        file_rows = cur.fetchall()

        if len(file_rows) != stored_count:
            print (' Database inconsitency found!\n')
            print (' Expecting {0} duplicates, found {1}.'.format(
                    stored_count,len(file_rows)))

        # as long as we found at least one, loop to display all
        for file_row in file_rows:
            
            # Parse each file _row for the hash and number of duplicates 
            stored_filename = file_row[0]
            stored_directory = file_row[2]
            
            # Construct and print the full filename
            full_stored_name = os.path.join(stored_directory,stored_filename)
            print ('  {}'.format(full_stored_name))
    
    # Done reading from the db
    con.close() 
    
    return(1)


###############################################################################
# List all files and associated hashes in the verification database
###############################################################################

def list_database(verification_database):

    #Check to ensure db exists
    if os.path.isfile(verification_database):
        con = sqlite3.connect(verification_database)
        cur = con.cursor()
    else:
        # Error
        print ('Database file "{}"" does not exist!'.format(verification_database))
        return(1)
    
    cur.execute("SELECT * FROM files")

    file_rows = cur.fetchall()

    # as long as we found at least one, loop to display all
    for file_row in file_rows:
        
        # Parse each file _row for the hash and number of duplicates 
        stored_filename = file_row[0]
        stored_hash = file_row[1]
        stored_directory = file_row[2]
        
        # Construct and print the full filename
        full_stored_name = os.path.join(stored_directory,stored_filename)
        print ('{0},{1}'.format(full_stored_name,stored_hash))
    
    # Done reading from the db
    con.close() 
    
    return(0)


###############################################################################
# List all the base path of the database
###############################################################################

def list_base_path(verification_database):

    #Check to ensure db exists
    if os.path.isfile(verification_database):
        con = sqlite3.connect(verification_database)
        cur = con.cursor()
    else:
        # Error
        print ('Database file "{}"" does not exist!'.format(verification_database))
        return(1)
    
    cur.execute("SELECT directory FROM directories")

    base_path = cur.fetchone()[0]

    print ('Base path: "{}"'.format(base_path))
    
    # Done reading from the db
    con.close() 
    
    return(0)


###############################################################################
# Display verification results
###############################################################################

def display_verification_results(files_dict,virus_total_check):
    
    print ('\n\nVerification results:')
    print ('---------------------\n')
    
    problems_found=0
    print_VT_hash_check.has_been_called = False

    # Print out files not found
    for key in files_dict:
        if files_dict[key][0]=='Missing':
            problems_found+=1
            print ('File not found: {}\n'.format(key))

    # Print out hash mismatches 
    for key in files_dict:
        if files_dict[key][0]=='Mismatch':
            
            hash_type=files_dict[key][1]
            orignal_hash=files_dict[key][2]
            current_hash=files_dict[key][3]
            original_signtool_output_hash=files_dict[key][4]
            current_tool_output_hash=files_dict[key][5]
            original_signtool_output=files_dict[key][6]
            current_signtool_output=files_dict[key][7]

            print('Mismatch found: {}'.format(key))

            if orignal_hash != current_hash:
                problems_found+=1
                print ('  {} hash mismatch:'.format(hash_type.upper()))
                print ('    Stored Hash:  {}'.format(orignal_hash))
                print ('    Current Hash: {}\n'.format(current_hash))

            if original_signtool_output_hash != current_tool_output_hash:
                problems_found+=1
                print ('  Signtool certificate chain mismatch:')
                print ('    Stored chain:\n{}'.format(original_signtool_output))
                print ('    Current chain:\n{}'.format(current_signtool_output))

            # See if we are performing Virus Total hash checks
            if virus_total_check:              
                print_VT_hash_check(files_dict[key][1],files_dict[key][3])
            print
    
    # Print out files not in the database 
    for key in files_dict:
        if files_dict[key][0]=='New':
            problems_found+=1
            hash_type=files_dict[key][1]
            hash_value=files_dict[key][2]
            print ('New file found: {}'.format(key))
            print ('  {0} hash value: {1}'.format(hash_type.upper(),hash_value))
            # See if we are performing Virus Total hash checks
            if virus_total_check:
                print_VT_hash_check(files_dict[key][1],files_dict[key][2])
            print

    print ('{} files processed\n'.format(len(files_dict)))

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
    parser.add_argument('-d', '--directory', help='directory to add')
    parser.add_argument('-ht', '--hashtype', help='hashing algorithm to use (defaults to SHA1)')
    parser.add_argument('-f', '--force', action='store_true', help='force an overwrite of an existing database')
    parser.add_argument('-t', '--type', action='append', help='filename types to add')
    
    # Only allow exe option on Windows and Mac:
    if windows_os() or mac_os():
        parser.add_argument('-exe', '--executables', action='store_true', help = 'Select executable files (Mac OS or Windows only)')
    
    parser.add_argument('-r', '--recursive', action='store_true', help = 'turn on recursive adding of directories')
    parser.add_argument('-u', '--update', action='store_true', help = 'update database to include changes to directories and hashes')
    parser.add_argument('-vt', '--virustotal', action='store_true', help = 'run new file hashes and hash mismatches through Virus Total')
    
    # only allow signtool if we are in windows
    if windows_os():
        parser.add_argument('-st', '--signtool', action='store_true', help = 'Check windows verification signature chain')
    
    parser.add_argument('-dup', '--duplicates', action='store_true', help = 'List all files with duplicate hashes in the database')
    parser.add_argument('-lbp', '--listbasepath', action='store_true', help = 'Display the base path of the database entries')
    parser.add_argument('-rbp', '--replacebasepath', help = 'New base path to use for verification')
    parser.add_argument('-l', '--list', action='store_true', help = 'List all files and their hashes in the database')
    parser.add_argument('database', help='name of hash database to use')
    
    args = parser.parse_args()
    
    if args.update and args.replacebasepath:
        print('Cannot update the database if changing the basepath!')
        print('Create new database with -f option to force overwrite of existing database')
        _exit(1)

    # If exe type is selected, then check to ensure we are on a MS Windows 
    # based OS then use 35 "High Risk" executable file types.  Comprehensive 
    # list found at:
    # https://www.lifewire.com/list-of-executable-file-extensions-2626061
    # Inspired by Cody Welu in my CSC 842 class with his Get-Hashes PS script
    #
    # Also check to see if we are on a Mac OS as there are a few common
    # exeuctable filetypes known for there as well...

    if args.executables:
        if windows_os():
            extensions=['*.BAT','*.CMD','*.COM','*.CPL','*.EXE','*.GADGET',
                        '*.INF1','*.INS','*.INX','*.ISU','*.JOB','*.JSE',
                        '*.LNK','*.MSC','*.MSI','*.MSP','*.MST','*.PAF',
                        '*.PIF','*.PS1','*.REG','*.RGS','*.SCR','*.SCT',
                        '*.SHB','*.SHS','*.U3P','*.VB','*.VBE','*.VBS',
                        '*.VBSCRIPT','*.WS','*.WSF','*.WSH','*.BIN']
        elif mac_os():
            extensions=['*.ACTION','*.APP','*.BIN','*.COMMAND','*.OSX',
                        '*.WORKFLOW','*.CSH']

        # fix args.type to include extensions
        if args.type:
            args.type+=extensions   
        else: 
            args.type = extensions
       
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
    if args.directory:
        error_val=add_to_database(hashtype,args.type,args.directory,args.recursive,
                                    args.database,args.signtool,args.force)

    # otherwise check to see if we are looking for duplicates 
    elif args.duplicates:
        error_val=list_duplicates(args.database)

    # otherwise check to see if we are listing the database contents
    elif args.list:
        error_val=list_database(args.database)

    elif args.listbasepath:
        error_val=list_base_path(args.database)

    # If we are not adding files, we are verifying or updating database
    else:
        # Create empty dictionary to hold all files and associated info we find
        files_dict = {}
        # Call verification function which puts all info we find from the 
        # verification process into files_dict
        error_val=verify_against_database(args.database, args.replacebasepath, files_dict)
        if error_val:
            _exit(error_val)
        else:
            if args.update:
                error_val=update_database(args.database, files_dict)
            else:
                error_val=display_verification_results(files_dict, args.virustotal)

    _exit(error_val)

###############################################################################
# Call main program if run directly, ie not run as a module
###############################################################################

if __name__ == '__main__':
    main()
