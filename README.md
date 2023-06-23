# py-mpq
An experimental python fork of the [StormLib](https://github.com/ladislav-zezula/StormLib) library for manipulating MPQ archives found in some Blizzard games.

Initially focused on modifying Warcraft III map files, even when the listfile has been removed.

Stormlib automatically opens such archives as readonly, despite modification being possible; this library adressess that limitation by encoding the file hashes as part of the file name when extracting anonymous files, allowing them to be repacked into an archive without ever needing to know what the name was.

## Usage

`py-mpq.py extract [mpq_file]`

Given an mpq file, extract all the files it contains into a directory `mpq_file`_data

`py-mpq.py create [mpq_directory]`

Given a directory created by `extract`, re-archive the contents back into an MPQ archive.