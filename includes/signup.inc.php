<?php 

if (isset($_POST['signup'])) {
	
	require 'dbh.inc.php';

	$username = $_POST['uid'];
	$email = $_POST['mail'];
	$password = $_POST['pwd'];
	$passwordRepeat = $_POST['pwd-repeat'];
	
	if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
		header("Location: ../signup.php?error=emptyfields&uid=".$username."&mail=".$email);
		exit();
	}else if(!filter_var($email, FILTER_VALIDATE_EMAIL) && !preg_match("/^[a-zA-Z0-9]*$/", $username)){
        header("Location: ../signup.php?error=invalidmailuid");
		exit();
	}else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header("Location: ../signup.php?error=invalidmail&uid=".$username);
		exit();
	}else if (!preg_match("/^[a-zA-Z0-9]*$/", $username)) {

    			header("Location: ../signup.php?error=invaliduid&mail=".$email);
				exit();

}else if ($password !== $passwordRepeat) {
			header("Location: ../signup.php?error=passwordcheck&mail=".$email."&uid=".$username);
			exit();
}else{
    //checking if email already exist in database or not
    $sql = "SELECT emailUsers FROM users WHERE emailUsers=?";

    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql) )  {

header("Location: ../signup.php?error=sqlerror");
		exit();

    }else{

    	mysqli_stmt_bind_param($stmt, "s", $email);
    	mysqli_stmt_execute($stmt);
    	mysqli_stmt_store_result($stmt);
    	$resultCheck1 = mysqli_stmt_num_rows($stmt);
    	
    	if ($resultCheck1 > 0 ) {

        header("Location: ../signup.php?error=emailtaken&user=".$username);
		exit();

    	}else{

            //checking if username already exist in database or not
            $sql = "SELECT uidUsers FROM users WHERE uidUsers=?";

            $stmt = mysqli_stmt_init($conn);

            if (!mysqli_stmt_prepare($stmt, $sql) )  {

                header("Location: ../signup.php?error=sqlerror");
		        exit();

        }else{

    	    mysqli_stmt_bind_param($stmt, "s", $username);
    	    mysqli_stmt_execute($stmt);
    	    mysqli_stmt_store_result($stmt);
    	    $resultCheck = mysqli_stmt_num_rows($stmt);
    
    	    if ($resultCheck > 0 ) {

            header("Location: ../signup.php?error=usertaken&email=".$username);
		    exit();

    	    }else{

    		    $sql ="INSERT INTO users (uidUsers, emailUsers, pwdUsers) VALUES (?, ?, ?)";
    		    $stmt = mysqli_stmt_init($conn);
   
    		    if (!mysqli_stmt_prepare($stmt, $sql)) {

                 header("Location: ../signup.php?error=sqlerror");
		         exit();
 
            }else{
            //hashing password
    	    $hashedPwd = password_hash($password, PASSWORD_DEFAULT);
        	mysqli_stmt_bind_param($stmt, "sss", $username, $email, $hashedPwd);
    	    mysqli_stmt_execute($stmt);

    	    header("Location: ../signup.php?signup=success");
		    exit();

       }
      }
     }
    }
   }
   //closing connection to save some data
mysqli_stmt_close($stmt);
mysqli_close($conn);
  }
    
    }else{

    	header("Location: ../signup.php");
		exit();
}
