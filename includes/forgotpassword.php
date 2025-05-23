<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

session_start();
try {
    $dbh = new PDO('mysql:host=localhost;dbname=aarogya_v1.2_db', 'root', '');
    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo 'Connection failed: ' . $e->getMessage();
    exit;
}

if (isset($_POST['sendotp'])) {
  $email = $_POST['email'];
  $mobile = $_POST['mobile'];

  // Generate a random OTP
  $otp = rand(100000, 999999);

  // Save OTP to the session
  $_SESSION['otp'] = $otp;
  $_SESSION['email'] = $email;
  $_SESSION['mobile'] = $mobile;

  // Fetch the sender email from the database
  $sql = "SELECT EmailId FROM tblusers WHERE EmailId=:email";
  $query = $dbh->prepare($sql);
  $query->bindParam(':email', $email, PDO::PARAM_STR);
  $query->execute();
  $result = $query->fetch(PDO::FETCH_OBJ);

  if ($result) {
      $senderEmail = $result->EmailId; // Use the fetched email address

      // Send OTP via email
      $mail = new PHPMailer(true);
      try {
          //Server settings
          $mail->isSMTP();
          $mail->Host = 'smtp.gmail.com';  // Specify main and backup SMTP servers
          $mail->SMTPAuth = true;
          $mail->Username = 'muharamnurain@gmail.com';   // SMTP username
          $mail->Password = 'iqaxezpibvcsqowf';     // SMTP password
          $mail->SMTPSecure = 'tls';
          $mail->Port = 587;

          //Recipients
          $mail->setFrom($senderEmail, 'Password Recovery'); // Use the fetched email address
          $mail->addAddress($email, 'User  '); // Send OTP to the user's email

          // Content
          $mail->isHTML(true);
          $mail->Subject = 'Your OTP for Password Reset';
          $mail->Body    = 'Your OTP for password reset is ' . $otp;

          $mail->send();
          echo "OTP has been sent to your email";
      } catch (Exception $e) {
          echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
      }
  } else {
      echo "No user found with that email address.";
  }
  exit;
}

if (isset($_POST['verifyotp'])) {
  $entered_otp = $_POST['otp'];
  $email = $_SESSION['email'];
  $mobile = $_SESSION['mobile'];

  if ($entered_otp == $_SESSION['otp']) {
      // Proceed to update the password
      $newpassword = $_POST['newpassword'];
      $hashed_password = password_hash($newpassword, PASSWORD_DEFAULT);
      
      $sql = "SELECT EmailId FROM tblusers WHERE EmailId=:email and ContactNo=:mobile";
      $query = $dbh->prepare($sql);
      $query->bindParam(':email', $email, PDO::PARAM_STR);
      $query->bindParam(':mobile', $mobile, PDO::PARAM_STR);
      $query->execute();
      $results = $query->fetchAll(PDO::FETCH_OBJ);
      
      if ($query->rowCount() > 0) {
          $con = "update tblusers set Password=:newpassword where EmailId=:email and ContactNo=:mobile";
          $chngpwd1 = $dbh->prepare($con);
          $chngpwd1->bindParam(':email', $email, PDO::PARAM_STR);
          $chngpwd1->bindParam(':mobile', $mobile, PDO::PARAM_STR);
          $chngpwd1->bindParam(':newpassword', $hashed_password, PDO::PARAM_STR);
          $chngpwd1->execute();
          echo "Your Password has been successfully changed";
      } else {
          echo "Email id or Mobile no is invalid";
      }
  } else {
      echo "<script>alert('Invalid OTP. Please try again.');</script>";
  }
  exit;
}
?>

  <script type="text/javascript">
function sendOtp() {
    var email = document.sendotp.email.value;
    var mobile = document.sendotp.mobile.value;
    
    $.ajax({
        type: "POST",
        url: "",
        data: {email: email, mobile: mobile, sendotp: "sendotp"},
        success: function(response) {
            alert("OTP has been sent to your email");
        }
    });
    return false;
}

function valid()
{
    if(document.chngpwd.newpassword.value!= document.chngpwd.confirmpassword.value)
    {
        alert("New Password and Confirm Password Field do not match  !!");
        document.chngpwd.confirmpassword.focus();
        return false;
    }
    return true;
}
</script>
<div class="modal fade" id="forgotpassword">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        <h3 class="modal-title">Password Recovery</h3>
      </div>
      <div class="modal-body">
<div class="row">
          <div class="forgotpassword_wrap">
            <div class="col-md-12">
              <form name="sendotp" method="post" onsubmit="return sendOtp();">
                <div class="form-group">
                  <input type="email" name="email" class="form-control" placeholder="Your Email address*" required="">
                </div>
                <div class="form-group">
                  <input type="text" name="mobile"class="form-control" placeholder="Your Reg. Mobile*" required="">
                </div>
                <div class="form-group">
                    <input type="submit" value="Send OTP" class="btn btn-block">
                </div>
              </form>

              <form action="" name="verifyotp" method="post" onsubmit="return valid();">
                <input type="hidden" name="verifyotp" value="1">
                <div class="form-group">
                  <input type="text" name="otp" class="form-control" placeholder="Enter OTP*" required=""> 
                </div>
                <div class="form-group">
                  <input type="password" name="newpassword" class="form-control" placeholder="New Password*" required="">
                </div>
                <div class="form-group">
                  <input type="password" name="confirmpassword" class="form-control" placeholder="Confirm Password*" required="">
                </div>
                <div class="form-group">
                  <input type="submit" value="Reset My Password" name="verifyotp" class="btn btn-block">
                </div>
              </form>

              <div class="text-center">
                <p class="gray_text">For security reasons we don't store your password. Your password will be reset and a new one will be sent.</p>
                <p><a href="#loginform" data-toggle="modal" data-dismiss="modal"><i class="fa fa-angle-double-left" aria-hidden="true"></i> Back to Login</a></p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>