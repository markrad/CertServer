// var token = null;

function onSignIn(event) {
    event.preventDefault();
    console.log('Sign in');
    let frm = $('#loginForm');
    $.ajax({
        type: frm.attr('method'),
        url: frm.attr('action'),
        data: frm.serialize(),
        success: function(data) {
            console.log(data);
            if (data.success == true) {
                sessionStorage.setItem('token', data.token);
                window.location.href = '/';
            } else {
                alert('Sign in failed: No reasone was provided');
            }
        },
        error: function(data) {
            console.log(data);
            alert(`Sign in failed ${data.responseJSON.messages[0].message}`);
        }
    });
}