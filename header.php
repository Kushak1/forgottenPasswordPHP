<?php
    	session_start();
 ?>
<!DOCTYPE html>
<html>
<head>
  <meta charset = "utf-8">
  <meta name = "description" content = "this is an example of meta description. this">
  <meta name = viewport content = "width = device-width, initial-scale = 1">
  <title></title>
  <link rel="stylesheet" href="style.css">
  </head>
  <body>
  <header id="header">
  	<nav class="main-wrapper">
  		<a class="header-logo" href="index.php">
  			<img class="st" src="img/jojo.png" alt="jojo">
  		</a>
  		<ul>
  			<li>
  				<a href="index.php">Home</a>
  			</li>
  			<li>
  				<a href="#">Portfolio</a>
  			</li>
  			<li>
  				<a href="#">About me</a>
  			</li>
  			<li>
  				<a href="#">Contact</a>
  			</li>
  		</ul>
  		<div class="nav-login">
  			<?php 
  				if (isset($_SESSION['userID'])) {
					echo 	"<form action='includes/logout.inc.php' method='post'>
  			
  							<button type='submit' name='logout-submit'>Logout</button>";

				}else{
					echo 	"<form action='includes/login.inc.php' method='post'>
  							<input type='text' name='mailuid' placeholder='Username/E-mail...'>
  							<input type='password' name='pwd' placeholder='Password...'>
  							<button type='submit' name='login-submit'>Login</button>
  							</form>
  							<a href='signup.php'>Signup</a>";

		}
  			?>

  			  			</form>
  		</div>
  	</nav>
  </header>