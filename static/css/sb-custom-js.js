$(document).ready(function(){
	$('#reg_submit').attr('disabled','disabled');
	$('#submit').attr('disabled', 'disabled');
})
$('#confirmPassword').focus( function(){
	$('#confirmPassword').mouseout( function(){
		if ($('#inputPassword').val() != $('#confirmPassword').val()){
			$('.error').html('');
			$('.error').html('Incorrect Password');
			$('#reg_submit').attr('disabled','disabled');
		}
		else{
			$('.error').html('');
			$('#reg_submit').removeAttr('disabled','disabled');
		}
	})
})


function fileError(){
				// fdatas = $('#form').serialize();
				fdatas = new FormData();
				files= $('#book_file')[0].files[0];
				fdatas.append('file', files);
				fdatas.append('csrf_token', '{{ csrf_token() }}');
				// fdata = $('#book_file').val();
				// urldata= "textstr="+fdatas;
				
				$.ajax({
					url:'/admin/confirmbookfiletype',
					data:fdatas,
					type:'POST',
					dataType:'text',
					contentType:false,
					processData:false,
					success:function(tt){
					if (tt == 'typebad'){
						$('#errorfile').html('');
						$('#errorfile').html("Incorrect file type");
						$("#book_file").val('');
					}
					else if (tt == 'sizebad'){
						$('#errorfile').html('');
						$('#errorfile').html("file must be 2mb or less");
						$("#book_file").val('');
					}
					else{
						$('#errorfile').html('');
						$('#submit').removeAttr('disabled', 'disabled');
					}
					},
					error:function(anye){	
					console.log(anye);
							
					}
				});
				}

