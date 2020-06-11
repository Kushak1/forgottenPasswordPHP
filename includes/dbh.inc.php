<?php
//your server name
$servername = "xxx";
//username of your server
$dBUsername = "xxx";
//password of your database
$dBPassword = "xxx";
//name of your database
$dBName = "xxx";

$conn = mysqli_connect($servername, $dBUsername, $dBPassword, $dBName);

if (!$conn) {
	die("Connection failed: ".mysqli_connect_error());

}