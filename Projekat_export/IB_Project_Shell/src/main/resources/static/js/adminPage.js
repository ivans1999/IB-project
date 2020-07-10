$(document).ready(function(){(
		
var table = $('#tabelaKorisnika'); 
var emailInput = $('#emailInput');
var inputActive = $('#activeInput');
var inputAuthority = $('#authorityInput');

function getUserByEmail (email) {
    	$.get('api/users/user/email', {'email': email},
    		function(response){
    			$('#tabelaKorisnika tr').not(function(){ return !!$(this).has('th').length; }).remove();
				console.log(response);
				addUser(response);
		}).fail(function(){
			console.log("error")
		});
 }
});