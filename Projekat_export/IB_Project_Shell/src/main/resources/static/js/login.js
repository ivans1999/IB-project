$(document).ready(function(){
	
	$('#loginSubmit').on('click', function(event) {
		event.preventDefault();
		var emailInput = $('#emailInput');
		var passwordInput = $('#passwordInput');
		
		var email = emailInput.val();
		var password = passwordInput.val();
		
		if($('#emailInput').val() == "" || $('#passwordInput').val() == ""){
            alert('Neka od obaveznih polja su prazna!');
            return;
        }
		
		$.post('api/users/user/login', {'email': email, 'password': password},
			function(response){
				var userEmail = response.email;
				sessionStorage.setItem('userEmail', userEmail);
				if(response.authority.name == 'Admin'){
					window.location.href = 'index.html';
				}else {
					window.location.href = 'index.html';
				}
		}).fail(function(){
			console.log("error")
		});
	});
});