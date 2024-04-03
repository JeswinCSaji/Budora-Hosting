$(document).ready(function () {
    $("#fn").keyup(function () {
        validateName("#fn");
    });

    $("#mail").keyup(function () {
        validateEmail("#mail");
    });

    $("#pass").keyup(function () {
        validatePassword("#pass");
    });

    $("#cpass").keyup(function () {
        validateConfirmPassword("#cpass");
    });
});
   
   function validateName(fieldId) {
    var name = $(fieldId).val().trim();
    var fullNameRegex = /^[A-Z][a-z]*(\s[A-Z][a-z]*)*$/;
    var words = name.split(' ');

    if (name === "") {
        $("#fnspan").html("Enter your full name and only alphabets are allowed").css("color", "red");
    } else if (words.length < 2) {
        $("#fnspan").html("Please enter your full name").css("color", "red");
    } else if (!fullNameRegex.test(name)) {
        $("#fnspan").html("Name should start with a capital letter and contain only alphabets and spaces").css("color", "red");
    } else {
        $("#fnspan").html("");
    }
   }
   
   function validateEmail(fieldId) {
   var email = $(fieldId).val();
   var filter = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
   if (email === "") {
   $("#emspan").html("Enter your Email Id").css("color", "red");
   } else if (!filter.test(email)) {
   $("#emspan").html("Incorrect Email Id").css("color", "red");
   } else {
   $("#emspan").html("");
   }
   }
   
   function validatePassword(fieldId) {
   var password = $(fieldId).val();
   var pattern = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])/;
   if (!pattern.test(password)) {
    if (password.length < 8) {
        $("#pspan").html("At least 8 characters").css("color", "red");
    }
    if (!/[0-9]/.test(password)) {
        $("#pspan").html("At least 1 number").css("color", "red");
    }
    if (!/[!@#$%^&*]/.test(password)) {
        $("#pspan").html("At least 1 symbol (!@#$%^&*)").css("color", "red");
        }
    if (!/[A-Z]/.test(password)) {
        $("#pspan").html("At least 1 capital letter").css("color", "red");
    }
    $("#pspan").html("Invalid password").css("color", "red");
    }
    $("#pspan").html("").css("color", "red");
    }
  
   function validateConfirmPassword(fieldId) 
   {
    var password = $("#pass").val();
   var confirmPassword = $(fieldId).val();
    if (confirmPassword === "") {
   $("#cpspan").html("Enter the password").css("color", "red");
   } else if (confirmPassword !== password) {
   $("#cpspan").html("Passwords do not match").css("color", "red");
   } else {
   $("#cpspan").html("");
   }
    }