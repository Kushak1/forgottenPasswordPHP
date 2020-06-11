<?php
require "header.php";?>

<main>
	<?php 
		if (isset($_SESSION['userID'])) {
			echo "<p class='text1'>You are logged in!</p>";

		}else{
			echo "<p class='text1'>You are logged out!</p>";

		}
	 ?>

</main>

<?php
require "footer.php";?>