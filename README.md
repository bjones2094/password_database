#Command-Line Password Database System
This system is designed to provide a simple, command line tool to 
create, modify and access encrypted password databases.
#Usage
The project is compiled into a single binary that is used through a 
series of commands to manage password databases. The current 
functionality only supports the use of randomly generated passwords of 
variable lengths (i.e. you can not add a pre-made password to a 
database).
#Encryption
The encryption of the databases is handled using the AES256 
implementation provided by libgcrypt. This means that building and 
running the binary requires access to this shared library.
#Database Format
The format for the encrypted database files can be seen in the graphic below:
![DB_FORMAT](pass.png?raw=true "Database Format")
#Disclaimer
This software is being created as an educational project, and should not be used to protect sensitive data. There is no guarantee of security through this software.
