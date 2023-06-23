# py-mpq
A python fork of the StormLib library for manipulating MPQ archives found in some Blizzard games.

Initially focused on modifying Warcraft III map files, even when the listfile has been removed. Stormlib automatically opens such archives as readonly, despite modification being possible; this library fixes that mistake by encoding the file hashes as part of the file name when extracting anonymous files, allowing them to be repacked into an archive without ever needing to know what the name was.
