<?php
error_reporting(E_ERROR | E_PARSE);
require "header.php";?>

<main>
	<div class="wrapper-main">
		<section class="section-default">
<h1 class="sign">Reset your password</h1>
<p class="resetemail">An e-mail will be send to you with instructions on how to reset your password.</p>

<form action="includes/reset-request.inc.php" method="post" class="nav-login">
	<input class="inputform" type="text" name="email" placeholder="Enter your e-mail address... ">
	<button type="submit" name="reset-request-submit" class="submitbutton">Receive new password by email</button>
</form>
<?php if (isset($_GET["reset"])) {

	if ($_GET["reset"] == "success") {
		
		echo '<p class="signupsuccess">Check your e-mail!</p>';
	}
	
}
?>
	  </section>
</div>

</main>

<?php
require "footer.php";?>