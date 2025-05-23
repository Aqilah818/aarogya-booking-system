<?php
// error_reporting(0);

// Server-side function to capitalize first letter of each word
function capitalizeFullNamePHP($name)
{
  $words = explode(' ', strtolower($name));
  foreach ($words as &$word) {
    if (strlen($word) > 0) {
      $word = ucfirst($word);
    }
  }
  return implode(' ', $words);
}

// Password strength checking function
function isPasswordStrong($password)
{
  $pattern = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/';
  return preg_match($pattern, $password);
}

if (isset($_POST['signup'])) {
  $fname = capitalizeFullNamePHP($_POST['fullname']);
  $email = $_POST['emailid'];
  $mobile = $_POST['mobileno'];
  $password = $_POST['password'];
  $confirmPassword = $_POST['confirmpassword'];

  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "<script>alert('Invalid email format. Please enter a valid email address.');</script>";
    exit;
  }

  if (!preg_match('/^01[0-9]{0,9}$/', $mobile)) {
    echo "<script>alert('Invalid mobile number. It must start with 01 and be exactly 11 digits long.');</script>";
    exit;
  }

  if (!isPasswordStrong($password)) {
    echo "<script>alert('Password is not strong enough. Please enter a stronger password.');</script>";
    exit;
  }

  if ($password !== $confirmPassword) {
    echo "<script>alert('Password and Confirm Password do not match.');</script>";
    exit;
  }

  // Check if mobile number already exists
  $sql = "SELECT ContactNo FROM tblusers WHERE ContactNo = :mobile";
  $query = $dbh->prepare($sql);
  $query->bindParam(':mobile', $mobile, PDO::PARAM_STR);
  $query->execute();

  if ($query->rowCount() > 0) {
    echo "<script>alert('Mobile number already registered. Please use a different number.');</script>";
    exit;
  }

  $hashed_password = password_hash($password, PASSWORD_DEFAULT);
  $sql = "INSERT INTO tblusers(FullName, EmailId, ContactNo, Password) VALUES(:fname, :email, :mobile, :password)";
  $query = $dbh->prepare($sql);
  $query->bindParam(':fname', $fname, PDO::PARAM_STR);
  $query->bindParam(':email', $email, PDO::PARAM_STR);
  $query->bindParam(':mobile', $mobile, PDO::PARAM_STR);
  $query->bindParam(':password', $hashed_password, PDO::PARAM_STR);
  $query->execute();

  if ($dbh->lastInsertId()) {
    echo "<script>alert('Registration successful. Now you can login');</script>";
  } else {
    echo "<script>alert('Something went wrong. Please try again');</script>";
  }
}
?>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
  function checkAvailability() {
    $.ajax({
      url: "check_availability.php",
      data: { emailid: $("#emailid").val() },
      type: "POST",
      success: function(data) {
        $("#user-availability-status").html(data);
      }
    });
  }

  function capitalizeFullName(input) {
    let words = input.value.toLowerCase().split(' ');
    for (let i = 0; i < words.length; i++) {
      if (words[i].length > 0) {
        words[i] = words[i][0].toUpperCase() + words[i].substring(1);
      }
    }
    input.value = words.join(' ');
  }

function validateMobile(input) {
  input.value = input.value.replace(/[^0-9]/g, '');

  let mobileError = document.getElementById('mobile-error');
  const mobile = input.value;

  if (!mobile.startsWith('01')) {
    mobileError.textContent = "Mobile number must start with 01.";
    $("#submit").prop("disabled", true);
  } else if (mobile.length > 11) {
    input.value = mobile.slice(0, 11);
    mobileError.textContent = "";
  } else {
    mobileError.textContent = "";
    $("#submit").prop("disabled", false);
  }

  if (mobile.length <= 11 && mobile.startsWith('01')) {
    checkMobileAvailability();
  }
}


  function checkMobileAvailability() {
    const mobile = $("#mobileno").val();
    $.ajax({
      type: "POST",
      url: "check_availability.php",
      data: { mobileno: mobile },
      success: function(data) {
        $("#mobile-error").html(data);
        if (data.includes("already exists")) {
          $("#submit").prop("disabled", true);
        } else {
          $("#submit").prop("disabled", false);
        }
      }
    });
  }

  function checkPasswordStrength() {
    const password = $("#password").val();
    const strength = getPasswordStrength(password);
    const feedback = $("#password-strength");
    const submit = $("#submit");

    if (strength < 3) {
      feedback.text("Weak").css("color", "red");
      submit.prop("disabled", true);
    } else if (strength === 3) {
      feedback.text("Medium").css("color", "orange");
      submit.prop("disabled", true);
    } else {
      feedback.text("Strong").css("color", "green");
      submit.prop("disabled", false);
    }
  }

  function getPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[!@#$%^&*]/.test(password)) strength++;
    return strength;
  }

  function checkPasswordMatch() {
    const password = $("#password").val();
    const confirmPassword = $("#confirmpassword").val();
    const submit = $("#submit");
    if (password !== confirmPassword) {
      $("#password-strength").text("Passwords do not match.").css("color", "red");
      submit.prop("disabled", true);
      return false;
    }
    return true;
  }
</script>

<!-- Sign Up Button -->
<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#signupform">Sign Up</button>

<!-- Sign Up Modal -->
<div class="modal fade" id="signupform">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">Sign Up</h3>
        <button type="button" class="close" data-dismiss="modal">&times;</button>
      </div>

      <div class="modal-body">
        <form method="post" name="signup" onsubmit="return checkPasswordMatch();">
          <div class="form-group">
            <input type="text" class="form-control" name="fullname" id="fullname" placeholder="Full Name" required oninput="capitalizeFullName(this)">
          </div>

          <div class="form-group">
            <input type="text" class="form-control" name="mobileno" id="mobileno" placeholder="Mobile Number (starts with 01)" maxlength="11" required oninput="validateMobile(this)" pattern="01[0-9]{0,9}" title="Mobile number must start with 01 and be up to 11 digits long">
            <span id="mobile-error" style="color:red; font-size:12px;"></span>
          </div>

          <div class="form-group">
            <input type="email" class="form-control" name="emailid" id="emailid" onblur="checkAvailability()" placeholder="Email Address" required>
            <span id="user-availability-status" style="font-size:12px;"></span>
          </div>

          <div class="form-group">
            <input type="password" class="form-control" name="password" id="password" placeholder="Password" required oninput="checkPasswordStrength()">
            <small>Password must be at least 8 characters long and contain at least one capital letter, one symbol, and one number.</small>
            <span id="password-strength" style="font-size:12px;"></span>
          </div>

          <div class="form-group">
            <input type="password" class="form-control" name="confirmpassword" id="confirmpassword" placeholder="Confirm Password" required>
          </div>

          <div class="form-group checkbox">
            <input type="checkbox" id="terms_agree" required checked>
            <label for="terms_agree">I Agree with <a href="#">Terms and Conditions</a></label>
          </div>

          <div class="form-group">
            <input type="submit" value="Sign Up" name="signup" id="submit" class="btn btn-block btn-primary">
          </div>
        </form>
      </div>

      <div class="modal-footer text-center">
        <p>Already got an account? <a href="#loginform" data-toggle="modal" data-dismiss="modal">Login Here</a></p>
      </div>
    </div>
  </div>
</div>
