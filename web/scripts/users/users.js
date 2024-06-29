
/**
 * Opens the user pane and retrieves the list of users from the server.
 * Populates the user list with the retrieved data.
 * 
 * @param {Event} event - The event object that triggered the function.
 * @returns {Promise<void>} - A promise that resolves when the user pane is opened and the user list is populated.
 */
async function openUserPane(event) {
    let header = `
        <li class="user-line">
            <div class="user-line-inner">
                <span class="user-name-title user-name">User Name</span>
                <span class="user-role-title user-role">User Role</span>
                <span class="user-buttons"></span>
            </div>
        </li>    `;
    $('.top-section').hide();
    $('.certs-view').hide();
    $('.keys-view').hide();
    $('.users-view').show();
    if (sessionStorage.getItem('role') !== '0') {
        $('#add-user-btn').hide();
    }

    try {
        let data = await lineCache.getFromServer('/api/getUsers');
        let userList = $('#userList');
        userList.empty();
        if (data.length == 0) {
            userList.append('<li class="empty">None</li>');
        }
        else {
            userList.append(header)
            data.forEach((user) => {
                userList.append(buildUserEntry(user));
            });
        }
    }
    catch (err) {
        showMessage(err);
    }
}

/**
 * Button handler that Hides the user pane and shows the top section, certs view, and keys view.
 * 
 * @param {Event} event - The event object.
 */
function exitUserPane(event) {
    $('.users-view').hide();
    $('.top-section').show();
    $('.certs-view').show();
    $('.keys-view').show();
}

/**
 * Builds the user entry HTML string from the user object.
 *
 * @param {Object} user - The user object.
 * @param {number} user.id - The user ID.
 * @param {string} user.username - The username.
 * @param {number} user.role - The user role (0 for ADMIN, 1 for USER).
 * @returns {string} The user entry HTML string.
 */
function buildUserEntry(user) {
    let userLine = `
        <li class="user-line" id=u${user.id}>
            <div class="user-line-inner">
                <span class="user-name">${user.username}</span>
                <span class="user-role">${user.role == 0 ? 'ADMIN' : 'USER'}</span>
                <span class="user-buttons">
                    <button class="button4" type="button" onclick="editUser(${user.id}, '${user.username}')">
                        <span class="button1Text">Edit</span>
                    </button>
                    <button class="button4 ${user.username != sessionStorage.getItem('userId') ? '' : 'hidden'}" type="button" onclick="deleteUser(${user.id}, '${user.username}')">
                        <span class="button1Text">Delete</span>
                    </button>
                </span>
            </div>
        </li>`;
    return userLine;
}

/**
 * Button click handler that opens the dialog to add a new user.
 * 
 * @param {Event} _event - The event object.
 */
function addUser(_event) {
    let dialog = $('#addUser');
    dialog.dialog('option', 'title', 'Add User');
    dialog.dialog('open');
}

/**
 * Handles the response after a user is added.
 *
 * @param {any} response - The response received after adding a user.
 */
function onUserAdded(response) {
    $('#addUserForm')[0].reset();
    $('#addUser').dialog('close');
    showMessage(response);
}

/**
 * Button click handler that opens the dialog to edit a user.
 * 
 * @param {number} id - The ID of the user.
 * @param {string} name - The name of the user.
 */
function editUser(id, name) {
    let dialog = $('#editUser');
    dialog.dialog('option', 'title', `Edit User ${name}`);
    $('#edit-userid').val(id);
    $('#edit-username').val(sessionStorage.getItem('userId'));
    dialog.dialog('open');
}

/**
 * Handles the response after a user is edited.
 *
 * @param {any} response - The response received after editing the user.
 */
function onUserEdited(response) {
    $('#editUserForm')[0].reset();
    $('#editUser').dialog('close');
    showMessage(response);
}

/**
 * Button click handler to deletes a user.
 * 
 * @param {number} id - The ID of the user to delete.
 * @param {string} name - The name of the user to delete.
 * @returns {Promise<void>} - A promise that resolves when the user is deleted.
 */
async function deleteUser(id, name) {
    if (confirm(`This will delete user ${name}. \n\nDo you wish to continue?`)) {
        try {
            let data = await lineCache.deleteFromServer(`/api/removeUser?id=${id}`);
            showMessage(data);
        }
        catch (err) {
            showMessage(err);
        }
    }
}

/**
 * Initializes the user functionality. Called when the page is loaded.
 */
function initUsers() {
    // Initialize the dialog boxes.
    $('#addUserForm').ajaxForm({
        dataType: 'json',
        success: onUserAdded,
        error: (xhr, _msg, _err) => {
            showMessage(xhr.responseJSON);
        }
    });

    $('#addUser').dialog({
        autoOpen: false,
        modal: true,
    });

    $('#editUserForm').ajaxForm({
        dataType: 'json',
        success: onUserEdited,
        error: (xhr, _msg, _err) => {
            showMessage(xhr.responseJSON);
        }
    });

    $('#editUser').dialog({
        autoOpen: false,
        modal: true,
    });
}
