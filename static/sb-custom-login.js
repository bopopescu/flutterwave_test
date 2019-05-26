function login(){
	data = $('#form').serialize()
	
	$.ajax({
		url: '/',
		data: data,
		type: 'POST',
		dataType: 'text',
		success:function(tt){
			if (tt == 'logged in'){
				$('.error').html('')
				document.location.href="{{ url_for('admin_dashboard') }}";
			}
			else if (tt == 'failed'){
				$('.error').html('Invalid Username or Password')
			}
			else{
				$('.error').html('an error occurred')
			}
			
		},
		error:function(anye){
			console.log(anye)
		}
	});
}