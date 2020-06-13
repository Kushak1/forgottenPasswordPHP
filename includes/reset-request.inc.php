<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


if (isset($_POST['reset-request-submit'])) {

	$selector = bin2hex(random_bytes(8));
	$token = random_bytes(32);
	//this will be the link you will send to user's email
	$url = "www.xxx/create-new-password.php?selector=" . $selector . "&validator=" . bin2hex($token);

	//token will expire after 1 hour
	$expires = date("U") + 3600;
	//connection with database
	require 'dbh.inc.php'; 

	$userEmail = $_POST["email"];

	$sql ="DELETE FROM pwdReset WHERE pwdResetEmail=?;";
	$stmt = mysqli_stmt_init($conn);

	if (!mysqli_stmt_prepare($stmt, $sql)) {

		echo"There was an error!";
		exit();

	} else {

		mysqli_stmt_bind_param($stmt, "s", $userEmail);
		mysqli_stmt_execute($stmt);

	}
	//making table in database 	which will contain data to send password
	$sql = "INSERT INTO pwdReset (pwdResetEmail, pwdResetSelector, pwdResetToken, pwdResetExpires) VALUES (?, ?, ?, ?);";

	$stmt = mysqli_stmt_init($conn);

	if (!mysqli_stmt_prepare($stmt, $sql)) {

		echo"There was an error111!";
		exit();

	} else {

		$hashedToken =password_hash($token, PASSWORD_DEFAULT);
		mysqli_stmt_bind_param($stmt, "ssss", $userEmail, $selector, $hashedToken, $expires);
		mysqli_stmt_execute($stmt);

	}

mysqli_stmt_close($stmt);
mysqli_close($conn);
//creating message which will be sent to email user provided
$to = $userEmail;

$subject = "reset your password for kushak's login system";

$message = "<p>We recieved a password reset request. The link to reset your password is bellow, you can ignore this email if you didn't request password change</p>';'";
$message .= "<p>Here is your password reset link: </br>";
$message .= "<a href='".$url."'>".$url." </a></p>";

$headers = "From: Kushak <mail@mail.com>\r\n";
$headers .= "Reply-To: Kushak <mail@mail.com>\r\n";
$headers .= "Content-type: text/html\r\n";

mail($to, $subject, $message, $headers);
//sending user back with success message
header("Location: ../reset-password.php?reset=success");
	
//returning user to main page if he acsess this file by acident
} else {

	header("Location: ../index.php");
	
}