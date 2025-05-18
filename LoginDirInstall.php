<?php
/*
    LoginDir Installer version  1.2.1 
    by Alessandro Lin - https://captcha-ajax.eu     Copyright 2025
*/

/**
 * LoginDir.php version 1.2.1
 * HTTP authentication at the server level,
 * password protecting directory and all of it's subfolders 
 * using .htaccess .htpasswd and PHP.
 * No need to have SSH access to the webserver.
 * LoginDir.php uses Bcrypt encryption.
 * 
 *   Usage:
 * - Put LoginDirInstall.php inside the folder to protect.
 * - Run LoginDirInstall.php. Keep the key otherwise you will have to repeat the installation.
 * 
 * - Run LoginDir.php?your_key and add new username and password, or 
 *   delete one username and password for the directory.
 * 
 * - Delete LoginDirInstall.php. Security reasons.
 * 
 * Emergency. Server Error 500
 * Remove all passwords and all users for directory manually:
 * - Edit .htaccess
 *      Deletes or comments on all lines between 
 *      # BEGIN Basic Block LoginDir and
 *      # END Basic Block LoginDir
 * - Delete .htpasswd 
 * OR
 * Verify that both .htpasswd and .htaccess files are present in the directory. 
 * If the one or both files are missing, correct .htaccess manually or / and 
 * restore (and rename) them from the backups contained in the LoginDirBackup folder. 
 */

$LoginDir1 = <<<'INI'
<?php
/**
 * LoginDir.php     version 1.2.1   May 2025
 * 
 * HTTP authentication at the server level,
 * password protecting directory and all of it's subfolders 
 * using .htaccess .htpasswd and PHP.
 * No need to have SSH access to the webserver.
 * LoginDir.php uses Bcrypt encryption.
 * 
 *   Usage:
 * - Put LoginDirInstall.php inside the folder to protect.
 * - Run LoginDirInstall.php. Keep the key otherwise you will have to repeat the installation.
 * 
 * - Run LoginDir.php?your_key and add new username and password, or 
 *   delete one username and password for the directory.
 * 
 * - Delete LoginDirInstall.php. Security reasons.
 * 
 * Emergency. Remove all passwords and all users for directory manually:
 * - Edit .htaccess
 *      Deletes or comments on all lines between 
 *      # BEGIN Basic Block LoginDir and
 *      # END Basic Block LoginDir
 * - Delete .htpasswd 
 * 
 * Server error 500:
 * Verify that both .htpasswd and .htaccess files are present in the directory. 
 * If the one or both files are missing, correct .htaccess manually or / and 
 * restore (and rename) them from the backups contained in the LoginDirBackup folder. 
 */
/**
 * Copyright 2025 Alessandro Lin - https://captcha-ajax.eu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

final class LoginDir {
    private $keyScript = '';

    function __construct($keyScript){        

        $this->keyScript = $keyScript;

        $this->Check_keyScript();

        $this->Main();        
    }

    private function Main(){
            // Check if the form has been submitted
        if ($_SERVER["REQUEST_METHOD"] == "POST") {

            ob_start();
            echo '<!DOCTYPE html><html><head><title>Password protect. Results</title></head><body>';

            // Initialize variables.
            $username = ''; $password = ''; $setDelete = '';

            $htpasswdFile = '.htpasswd'; $htaccessFile = '.htaccess';

            $username = $this->remove_Semicolons_And_Whitespace(trim($_POST['username']));
            $password = $this->remove_Semicolons_And_Whitespace(trim($_POST['password']));
            $setDelete = $this->remove_Semicolons_And_Whitespace(trim($_POST['SetDelete']));

            // Inputs exists?
            if( empty($username) || empty($password) || empty($setDelete) ){
                http_response_code(400);
                exit('Bad Request. One or more required fields are empty');
            }

            $this->Backups($htpasswdFile, $htaccessFile);   //backups of file password and .htaccess if exists

            switch ($setDelete) {
            case 'Set':
                $this->Set_newUser($password, $username, $htpasswdFile, $htaccessFile);                
                break;

            default:
                $this->Delete_user($htpasswdFile, $username, $password, $htaccessFile);
                break;
           }
        }   

        $this->Html_form();
    }

    /**
     * Remove semicolons ; Removes semicolons in many writing formats. 
     * remove Whitespaces. 
     * remove :  <  >  &lt; &gt; and other writing formats
     * Max lenght input = 24 chars
     */
    private function remove_Semicolons_And_Whitespace($input) {
        if (strlen($input) > 24) {
            http_response_code(400);
            exit('Bad Request. One or more required fields are too long. Max 24 chars.');
        }

        $count = 0;
        $output = preg_replace('/<|>|\\\74|\\\76|&lt;|&gt;|&#60;|&#62;|&#x3C;|&#x3E;|\\x{003C}|\\x{003E}/', '', $input, -1, $count);
        if($count){echo '<br> - ' . $count . ' entities removed';}

        $count = 0;
        $output = preg_replace('/[:]|[;]|\\\x3B|\\\u003B|\\\073|&semi;|%3B|'.chr(59).'/u', '', $output, -1, $count);
        if($count){echo '<br> - ' . $count . ' specialchar removed';}

        $count = 0;
        $output = preg_replace('/\s+/', '', $output, -1, $count);
        if($count){echo '<br> - ' . $count . ' white space removed';}
        return $output;
    }


    /**
     * Delete User and Password.
     */
    private function Delete_user( string $htpasswdFile, string $username, string $password, string $htaccessFile){

        $linesPasswdFile = [];
        $linesPasswdFile = file($htpasswdFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if(empty($linesPasswdFile)){     // $htpasswdFile has been deleted by someone. It's a message Server error 500
            http_response_code(500);
            exit('500 Server Error!');
        }

        $countUsersBefore = count($linesPasswdFile);
        $userDeleted = (bool)false;
                    
        $userToDelete = $username;
        $passwordToVerify = $password;
        
        $hashedPassword = null;
        
        foreach ($linesPasswdFile as $line) {
            list($userList, $hashedPassword) = explode(':', $line);
            if ($userList === $userToDelete) {
                break; // Exit the loop once the user is found
            }
        }

        // Check if the user was found and verify the password
        if ($hashedPassword !== null && password_verify($passwordToVerify, $hashedPassword)) {
            echo '<br> ------------------------------';

            if($countUsersBefore === (int)1){
                // remove file 
                unlink($htpasswdFile);
                $userDeleted = (bool)true;
            } 
            else {
                // Password is correct, proceed to delete the user
                foreach ($linesPasswdFile as $key => $line) {
                    list($userList, $hashedPassword) = explode(':', $line);
                    if ($userList === $userToDelete) {
                        unset($linesPasswdFile[$key]);
                        break;
                    }
                }
        
                file_put_contents($htpasswdFile, implode(PHP_EOL, $linesPasswdFile) . PHP_EOL);
                $userDeleted = (bool)true;
            }

            echo "<p><b> - User '$userToDelete' </b>has been deleted from the $htpasswdFile file.</p>";

        } else {
            // Password is incorrect or user not found
            echo "<p> - Password is incorrect or user '$userToDelete' not found.</p>";
            exit();
        }

        //  edit .htaccess file 
        if($userDeleted === (bool)true){

            if($countUsersBefore === (int)1){

                $lines = file($htaccessFile, FILE_IGNORE_NEW_LINES);

                $startMarker = '# BEGIN Basic Block LoginDir';
                $endMarker = '# END Basic Block LoginDir';

                $found = false;
                $subArray = [];
                $newArray = [];

                foreach ($lines as $element) {
                    if ($element === $startMarker) {
                        $found = true;
                        $subArray[] = $element;
                    } elseif ($found) {
                        $subArray[] = $element;
        
                        if ($element === $endMarker) {
                            $found = false;
                            continue;
                        }
                    } else {
                        $newArray[] = $element;
                    }
                }

                file_put_contents($htaccessFile, implode(PHP_EOL, $newArray) . PHP_EOL);
            }

        } else {
            echo "<br> - Password is incorrect or user '$userToDelete' not found #1.";
            exit();
        }
        exit();        
    }

    /**
     * Set new User and Password. Add one User.
     */
    private function Set_newUser( string $password, string $username, string $htpasswdFile, string $htaccessFile){
        // Hash the password using password_hash
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
        $entry = "$username:$hashedPassword\n";

        // Append the entry to the $htpasswdFile file
        file_put_contents($htpasswdFile, $entry, FILE_APPEND | LOCK_EX);
           
        // authentication configuration  .htaccess
        $htaccessContent = "\n";
        $htaccessContent .= "# BEGIN Basic Block LoginDir\n";
        $htaccessContent .= "AuthType Basic\n";
        $htaccessContent .= "AuthName \"Restricted Area\"\n";
        $htaccessContent .= "AuthUserFile " . realpath($htpasswdFile) . "\n";
        $htaccessContent .= "Require valid-user\n";
        $htaccessContent .= "# END Basic Block LoginDir\n";
                       
        if(!file_exists($htaccessFile)){
            // 1. File does not exist, write
            file_put_contents($htaccessFile, $htaccessContent, LOCK_EX);
        }            
        else {
            // 2. The file exists, check if the authentic block is already present inside the file
            $lines = file($htaccessFile, FILE_IGNORE_NEW_LINES);

            $startMarker = '# BEGIN Basic Block LoginDir';
            $endMarker = '# END Basic Block LoginDir';

            $found = false;
            $subArray = [];

            foreach ($lines as $element) {
                if ($element === $startMarker) {
                    $found = true;
                    $subArray[] = $element;
                } elseif ($found) {
                    $subArray[] = $element;
                    if ($element === $endMarker) {
                        break;
                    }
                }
            }

            if ($found && end($subArray) === $endMarker) {
                echo "<br> - .htaccess NOT modified ";
            } else {
                echo "<br> - .htaccess MODIFIED";
                file_put_contents($htaccessFile, $htaccessContent, FILE_APPEND | LOCK_EX);
            }
               
        }
        echo '<br> -----------------------------';
        echo "<p> - Password set for this directory and all of it's subfolders. ";
        echo "<br><b> user    : " . $username . "</b>";
        echo "<br><b> password: " . $password . "</b>";
        echo "</p>";

        exit(); 
    }

    /**
     * Backups of $htpasswdFile e .htaccess. 
     * Create or update the folder LoginDirBackup
     */
    private function Backups( string $htpasswdFile, string $htaccessFile ){
        echo '<br> ------------------------------';

        $htpassFileBak = '.htpasswd_ld.bak';
        $htaccesFilBak = '.htaccess_ld.bak';
        $Logindirbackup = 'LoginDirBackup';

        (is_dir('LoginDirBackup')) || (mkdir('LoginDirBackup'));

        if(is_file($htpasswdFile)){
            if(copy($htpasswdFile, $Logindirbackup . '/' . $htpassFileBak )){
                echo '<br> - Successful backup of ' . $htpasswdFile;
           }
       }
   
       if(is_file($htaccessFile)){
           if(copy($htaccessFile, $Logindirbackup . '/' . $htaccesFilBak )){
               echo '<br> - Successful backup of ' . $htaccessFile;
           }
       }
    }

    /**
     * Check if this script was called regularly, with correct key.
     * run LoginDir.php?Key
     */
    private function Check_keyScript(){
        $key = (parse_url($_SERVER['REQUEST_URI']));
        $hashPassword = $this->keyScript;
        if( empty(password_verify( htmlspecialchars( trim($key['query']) ), $hashPassword))) {            
            http_response_code(404);
            exit('Page NOT found!');
        }
    }

    /**
     * Output html form
     */
    private function Html_form(){
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password protect. Select</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-form { background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);padding-top: 0;  padding-right: 24px;  padding-left: 24px;}
        .login-form h3 { margin-bottom: 20px; }
        .login-form input { width: 100%; padding: 10px; margin: 10px -10px; border: 1px solid #ccc; border-radius: 5px; }
        .login-form button { width: 100%; padding: 10px; background-color: #5cb85c; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .login-form button:hover { background-color:rgb(60, 136, 60); }
        fieldset { border: 1px solid #ccc; padding: 10px; }
        .radio-group { display: flex; justify-content: center; gap: 10px; }
        input[type="radio"] { display: none; }
        .custom-radio { position: relative; padding-left: 30px; cursor: pointer; user-select: none; }
        .custom-radio:before { content: ''; position: absolute; left: 0; top: 50%; transform: translateY(-50%); width: 20px; height: 20px; border: 2px solid #007BFF; border-radius: 50%; background-color: white; transition: background-color 0.3s; }        
        input[type="radio"]:checked + .custom-radio:before { background-color: #007BFF; }
        input[type="radio"]:checked + .custom-radio:after { content: '';position: absolute; left: 6px; top: 50%; transform: translateY(-50%); width: 10px; height: 10px; border-radius: 50%; background-color: white; }
        .password-container { width: 94%; position: relative; display: inline-block; }
        #password { padding-right: 30px; }
        .toggle-password { position: absolute; right: -20px; top: 50%; transform: translateY(-50%); cursor: pointer; user-select: none; }
    </style>
    <script>
        var LD = LD || {}
        LD.togglePassword = function() { const passwordType = password.getAttribute('type') === 'password' ? 'text' : 'password'; password.setAttribute('type', passwordType); }
    </script>
</head>
<body>
<div class="login-form">
    <h3>
    <img style="display:inline !important;width: 32px;" src="data:image/png;base64,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">
    Choose username and<br> password to protect <br>this directory and <br>all its subdirectories. 
    </h3>
    <form action="" method="POST">
        <label for="username"><small> Username: </small></label>
        <input type="text" id="username" name="username" placeholder="Username" value="" required autofocus><br><br>

        <label for="password"><small> Password: </small></label>
        <div class="password-container">
            <input type="password" id="password"  name="password" placeholder="Password" required>
            <span class="toggle-password" onclick="LD.togglePassword()">👁️</span>
        </div><br><br>
        <fieldset>
            <legend><strong>Add</strong> new User or <strong>Delete</strong> User</legend>
            <div class="radio-group">
                <label>
                    <input type="radio" name="SetDelete" value="Set" checked>
                    <span class="custom-radio">Add</span>
                </label><br>
                <label>
                    <input type="radio" name="SetDelete" value="Delete">
                    <span class="custom-radio">Delete</span>
                </label><br>
            </div>
        </fieldset><br>
        <button type="submit">Submit</button><br>
        <a style="color: #a9bbbb;  font-size: 10px;" href="https://www.flaticon.com/free-icons/private" title="private icons">Private icons created by Freepik - Flaticon</a>
    </form>
</div>
</body>
</html>
    <?php
    }
}

INI;

// Select a pair: key e key hashed
$allchars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$letter = substr( $allchars, mt_rand(0, strlen($allchars)-1), 1 );

$number = (string)mt_rand(1, 9999);

$key = trim($letter . $number);
$keyHashed = password_hash($key, PASSWORD_DEFAULT);

$LoginDir2 = <<< INI

# ***  Run *** #
new LoginDir('{$keyHashed}');
INI;

$LoginDir = $LoginDir1 . $LoginDir2;

$msg = '';
If(file_put_contents('LoginDir.php', $LoginDir)) {

    $msg  = "<br>" . "LoginDir.php successfully installed.";
    $msg .= "<br>" . "Your key for LoginDir.php script is: " . $key;
    $msg .= '<br>' . 'Keep this key otherwise you will have to repeat the installation';
    $msg .= "<br>" . "Run: <br> LoginDir.php?" . $key;
    $msg .= "<br>" . "----------------------------------------------" . '<br>';
    $msg .= "<br>" . "Your key was randomly selected" . "<br>" . "by this installation script LoginDirInstall.php";
    $msg .= '<br>' . 'For security reasons, now it would be better to delete the file LoginDirInstall.php';
    $msg .= "<br>";
    echo $msg;

} else {
    $msg = '<br> Something went wrong. LoginDir.php was not installed.';
}