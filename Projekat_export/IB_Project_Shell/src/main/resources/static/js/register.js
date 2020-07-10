$(document).ready(function(){
	
	$('#registrationSubmit').on('click', function(event) {
		event.preventDefault();
		var emailInput = $('#emailInput');
		var passwordInput = $('#passwordInput');
		var passwordInputRepeat = $('#repeatedPasswordInput');
		
		var email = emailInput.val();
		var password = passwordInput.val();
		var passwordRepeat = passwordInputRepeat.val();
		
		if($('#emailInput').val() == "" || $('#passwordInput').val() == "" || $('#repeatedPasswordInput').val() == ""){
            alert('Neka od obaveznih polja su prazna!');
            return;
        }
		if($('#passwordInput').val() != $('#repeatedPasswordInput').val()){
            alert('Uneli ste razlicite lozinke!');
            return;
        }
		$.post('api/users/user/register', {'email': email, 'password': password},
			function(response){
				alert('Uspesno ste se registrovali!');
	            window.location.replace("userPage.html");
		}).fail(function(){
			console.log("error")
		});
	});
});