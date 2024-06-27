/**
 * Handles the sign-in event by sending a POST request to the server. If valid, the server will respond with a jwt token.
 * @param {Event} event - The sign-in event.
 */
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
                sessionStorage.setItem('expiresAt', data.expiresAt);
                sessionStorage.setItem('userId', data.userId);
                sessionStorage.setItem('role', data.role);
                window.location.href = '/';
            } else {
                alert('Sign in failed: No reason was provided');
            }
        },
        error: function(data) {
            console.log(data);
            alert(`Sign in failed ${data.responseJSON.messages[0].message}`);
        }
    });
}
