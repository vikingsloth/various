<title>Example IRC Network Captcha Service</title>
<html>
  <body bgcolor=black text=grey>
<font color=red size=5>(You've been stopped by the Gestapo) PAPERS PLEASE!<br><br></font>
    <form action="" method="post">
<?php

require_once('recaptchalib.php');

// Get a key from http://recaptcha.net/api/getkey
$publickey = "pubkey";
$privatekey = "privkey";

$db = mysql_connect('localhost', 'gestapo', 'mysqlpass')
  or die('Could not connect to mysql server');

mysql_select_db('gestapo', $db)
  or die('Could not find table in mysqldb');

$query = sprintf("SELECT user_key FROM captcha WHERE user_key='%s' AND completed=0",
                 mysql_real_escape_string($_REQUEST["key"]));

$res = mysql_query($query);

if(mysql_num_rows($res) <= 0) {
  echo "This captcha doesn't exist or has already been completed<br>";
  exit;
}

# the response from reCAPTCHA
$resp = null;
# the error code from reCAPTCHA, if any
$error = null;

# was there a reCAPTCHA response?
if ($_POST["recaptcha_response_field"]) {
        $resp = recaptcha_check_answer ($privatekey,
                                        $_SERVER["REMOTE_ADDR"],
                                        $_POST["recaptcha_challenge_field"],
                                        $_POST["recaptcha_response_field"]);

        if ($resp->is_valid) {
                $query = sprintf("UPDATE captcha SET completed=NOW(), post_ip='%s' WHERE user_key='%s'",
                            mysql_real_escape_string($_SERVER["REMOTE_ADDR"]),
                            mysql_real_escape_string($_REQUEST["key"]));

                mysql_query($query);

                echo "Success. Your access controls will be lifted.<br>";
                echo "Contact sloth@ww88.org if this fails to work.<br>";
                exit(0);
        } else {
                # set the error code so that we can display it
                $error = $resp->error;
        }
}
echo recaptcha_get_html($publickey, $error);
?>
    <br/>
    <input type="submit" value="submit" />
    </form>
  </body>
</html>
