<?php
include('includes/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];

    // Update the user's verification status in the database
    $sql = "UPDATE tblusers SET VerificationStatus = 1 WHERE EmailId = :email";
    $query = $dbh->prepare($sql);
    $query->bindParam(':email', $email, PDO::PARAM_STR);

    if ($query->execute()) {
        echo 'success';
    } else {
        echo 'error';
    }
}