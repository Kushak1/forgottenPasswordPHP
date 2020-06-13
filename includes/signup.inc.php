<?php 

if (isset($_POST['signup'])) {
	//making connection with mySQLi database
	require 'dbh.inc.php';
	//getting data from input
	$username = $_POST['uid'];
	$email = $_POST['mail'];
	$password = $_POST['pwd'];
	$passwordRepeat = $_POST['pwd-repeat'];
	//making sure user filled all fields
	if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
		header("Location: ../signup.php?error=emptyfields&uid=".$username."&mail=".$email);
		exit();
	//first making sure email AND username is valid if both incorret throw error
	}else if(!filter_var($email, FILTER_VALIDATE_EMAIL) && !preg_match("/^[a-zA-Z0-9]*$/", $username)){
        header("Location: ../signup.php?error=invalidmailuid");
		exit();
	//making sure email valid
	}else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header("Location: ../signup.php?error=invalidmail&uid=".$username);
		exit();
	//making sure username valid
	}else if (!preg_match("/^[a-zA-Z0-9]*$/", $username)) {

    			header("Location: ../signup.php?error=invaliduid&mail=".$email);
				exit();
//checking if password matching eachother
}else if ($password !== $passwordRepeat) {
			header("Location: ../signup.php?error=passwordcheck&mail=".$email."&uid=".$username);
			exit();
}else{
    //checking if email already exist in database or not
    $sql = "SELECT emailUsers FROM users WHERE emailUsers=?";

    $stmt = mysqli_stmt_init($conn);
    //making sure i can get data from database
    if (!mysqli_stmt_prepare($stmt, $sql) )  {

header("Location: ../signup.php?error=sqlerror");
		exit();

    }else{
    	//verifying there is no duplicate of users email in database
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
    	    	//inserting input in database
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
    //in case user accsess this page by accident return him
    }else{

    	header("Location: ../signup.php");
		exit();
}
