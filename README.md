# Protection with Username and Password of a directory and all its subdirectories.
* HTTP authentication at the server level,
* Security uses .htaccess .htpasswd and PHP.
* No need to have SSH access to the webserver.
* LoginDir.php uses Bcrypt encryption.
## Usage
- Put LoginDirInstall.php inside the folder to protect.
- Run &nbsp; **/Your-site-path-directory/LoginDirInstall.php** . <br>Keep the unique key that will be built, which is needed to run LoginDir.php, otherwise you will have to repeat the installation.
- Run &nbsp; **/Your-site-path-directory/LoginDir.php?your_key**  <br>and add new username and password, or delete one username and password for the directory.
- **Delete** LoginDirInstall.php. Security reasons.
### Emergency. Remove all passwords and all users for directory manually:
*  Edit .htaccess
    * Deletes or comments on all lines between<br> 
      ' # BEGIN Basic Block LoginDir ' and<br> 
      ' # END Basic Block LoginDir '
* Delete .htpasswd 

You can also use the backup copies of .htaccess and .htpasswd contained in the LoginDirBackup folder, created by LoginDir.php during use.


## Why use LoginDir.php ?
If you do not have SSH access or if you do not want to use it. 

If you don't want to look up the syntax and run the (web) server's inline commands to create username and password for the directory. 

If you do not have Sever Panel or if your panel does not have this feature.

## Output of Firefox when calling the protected directory:
<img src="https://captcha-ajax.eu/LoginDirAssetsGitHub/Http_Login_700.jpg" alt="Firefox_Output" width="300" height="auto">

## Changelog
### 1.2.1
* Added Installer


### 1.0.0
* Initial release

