$(document).ready(function () {
    $("#st").keyup(function () {
        validateStoreName("#st");
    });

    $("#fn").keyup(function () {
        validateName("#fn");
    });

    $("#mail").keyup(function () {
        validateEmail("#mail");
    });

    $("#contact").keyup(function () {
        validateContact("#contact");
    });

    $("#address").keyup(function () { 
        validateAddress("#address");
    });

    $("#landmark").keyup(function () { 
        validateLandmark("#landmark");
    });

    $("#pass").keyup(function () {
        validatePassword("#pass");
    });

    $("#cpass").keyup(function () {
        validateConfirmPassword("#cpass");
    });

});

function validateName(fieldId) {
    var name = $(fieldId).val();
    var lettersWithSpaces = /^[A-Za-z\s]+$/;
    if (name.trim() === "") {
        $("#fnspan").html("Enter your name").css("color", "red");
    } else if (!lettersWithSpaces.test(name)) {
        $("#fnspan").html("Only alphabets are allowed").css("color", "red");
    } else {
        $("#fnspan").html("");
    }
}
function validateStoreName(fieldId) {
    var storename = $(fieldId).val();
    var lettersWithSpaces = /^[A-Za-z\s]+$/;
    if (storename.trim() === "") {
        $("#stspan").html("Enter your store name").css("color", "red");
    } else if (!lettersWithSpaces.test(storename)) {
        $("#stspan").html("Only alphabets are allowed").css("color", "red");
    } else {
        $("#stspan").html("");
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
    var pattern = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/;
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


function validateConfirmPassword(fieldId) {
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

function validateContact(fieldId) {
    var con = $(fieldId).val();
    var filtercon = /^(\+91-|0)?[6-9]\d{9}$/;
    if (con === "") {
        $("#cnspan").html("Enter your Mobile Number").css("color", "red");
    } else if (!filtercon.test(con)) {
        $("#cnspan").html("Phone Number should be atleast 10 numbers and cannot contain alphabets").css("color", "red");
    } else {
        $("#cnspan").html("");
    }
}

function validateAddress(fieldId) {
    var con = $(fieldId).val();
    if (con === "") {
        $("#adspan").html("Enter your address").css("color", "red");
    } else {
        $("#adspan").html("");
    }
}

function validateLandmark(fieldId) {
    var con = $(fieldId).val();
    if (con === "") {
        $("#ldspan").html("Enter a Landmark").css("color", "red");
    } else {
        $("#ldspan").html("");
    }ldspan
}

