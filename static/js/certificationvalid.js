  $(document).ready(function () {
    $("#certification_image").change(function () {
      validateCertificationImage("#certification_image");
    });
  
    $("#owner_name").keyup(function () {
      validateOwnerName("#owner_name");
    });
  
    $("#store_name").keyup(function () {
      validateStoreName("#store_name");
    });
  
    $("#expiry_date_from").change(function () {
      validateExpiryDateFrom("#expiry_date_from");
    });
  
    $("#expiry_date_to").change(function () {
      validateExpiryDateTo("#expiry_date_to");
    });
});  
    function validateCertificationImage(fieldId) {
      var certificationImage = $(fieldId).val().trim();
      var certificationImageError = $("#certification_image_error");
      if (certificationImage === "") {
      $("#certification_image_error").html("Store License Image is required").css("color", "red");
        certificationImageError.text("Store License Image is required").css("color", "red");
      } else {
        $("#certification_image_error").html("").css("color", "red");
    }
    }
  
    function validateOwnerName(fieldId) {
      var ownerName = $(fieldId).val().trim();
      var lettersOnlyPattern = /^[A-Za-z\s]+$/;
  
      if (ownerName === "") {
        $("#owner_name_error").html("Enter your Owner name").css("color", "red");
      } else if (!lettersOnlyPattern.test(ownerName)) {
        $("#owner_name_error").html("Owner Name should contain only letters and spaces").css("color", "red");
     } else {
        $("#owner_name_error").html("");
    }
    }
  
    function validateStoreName(fieldId) {
      var storeName = $(fieldId).val().trim();
  
      if (storeName === "") {
        $("#store_name_error").html("Store Name is required").css("color", "red");
      } else {
        $("#store_name_error").html("").css("color", "red");
      }
    }
  
    function validateExpiryDateFrom(fieldId) {
      var expiryDateFrom = $(fieldId).val().trim();
      var datePattern = /^\d{2}-\d{2}-\d{4}-$/;
      var today = new Date().toISOString().slice(0, 10);
  
      if (expiryDateFrom === "") {
        $("#expiry_date_from_error").html("Expiry Date From is required").css("color", "red");
      } else if (!datePattern.test(expiryDateFrom) || expiryDateFrom > today) {
        $("#expiry_date_from_error").html("Expiry Date From should be in dd-mm-yyyy format and not after the current date or today").css("color", "red");
      } else {
        $("#expiry_date_from_error").html("").css("color", "red");
      }
    }
  
    function validateExpiryDateTo(fieldId) {
      var expiryDateTo = $(fieldId).val().trim();
      var datePattern = /^\d{2}-\d{2}-\d{4}-$/;
      var today = new Date().toISOString().slice(0, 10);
  
      if (expiryDateTo === "") {
        $("#expiry_date_to_error").html("Expiry Date To is required").css("color", "red");
      } else if (!datePattern.test(expiryDateTo) || expiryDateTo <= today) {
        $("#expiry_date_to_error").html("Expiry Date To is required").css("color", "red");
      } else {
        $("#expiry_date_to_error").html("").css("color", "red");
      }
    }
  
    // Add other validations if needed

  
