
/**
 * Called when a new CA is successfully created.
 * 
 * @param {{ message: string }} result result when creating a new CA
 */
function createCACertResponse(result) {
    $('#generateCAReset').trigger('click');
    showMessage(result);
}

/**
 * Open a new intermediate certificate dialog box.
 * 
 * @param {string} id id of the certificate that will sign this new intermediate 
 * @param {*} name name of the certificate that will sign this new intermediate
 */
function newIntermediateDialog(id, name) {
    let dialog = $('#newIntermediate');
    dialog.dialog('option', 'title', `${name} -> intermediate`);
    $('#intermediateSigner').val(id);
    dialog.dialog('open');
}

/**
 * Called when a new intermediate is successfully created.
 * 
 * @param {{ message: string }} result result when creating a new intermediate
 */
function createIntermediateCertResponse(result) {
    $('#generateIntermediateReset').trigger('click');
    showMessage(result);
    $('#newIntermediate').dialog('close');
}

/**
 * Called when the reset button is clicked on the new intermediate form.
 */
function resetIntermediateForm() {
    let signer = $('#intermediateSigner').val();
    $('#newIntermediateForm')[0].reset();
    $('#IntermediateSANList').empty();
    $('#intermediateSigner').val(signer);
}

/**
 * Open a new leaf certificate dialog box.
 * 
 * @param {string} id id of the certificate that will sign this new leaf 
 * @param {string} name name of the certificate that will sign this new leaf
 */
function newLeafDialog(id, name) {
    let dialog = $('#newLeaf');
    dialog.dialog('option', 'title', `${name} -> leaf`);
    $('#leafSigner').val(id);
    dialog.dialog('open');
}

/**
 * Called when a new leaf is successfully created.
 * 
 * @param {{ message: string }} result result when creating a new leaf
 */
function createLeafCertResponse(result) {
    $('#generateLeafReset').trigger('click');
    showMessage(result);
    $('#newLeaf').dialog('close');
}

/**
 * Called when the reset button is clicked on the new leaf form.
 */
function resetLeafForm() {
    let signer = $('#leafSigner').val();
    $('#newLeafForm')[0].reset();
    $('#LeafSANList').empty();
    $('#leafSigner').val(signer);
}

/**
 * Add a new subject alternative name input box to the new intermediate certificate dialog
 */
function AddIntermediateSAN() {
    let list = $('#IntermediateSANList');
    let input = $('#IntermediateSANInput');
    AddSAN(list, input);
}

/**
 * Add a new subject alternative name input box to the new leaf certificate dialog
 */
function AddLeafSAN() {
    let list = $('#LeafSANList');
    let input = $('#LeafSANInput');
    AddSAN(list, input);
}

/**
 * When the tick is clicked to accept a new SAN, this is called to add it to the current list of SANs.
 * 
 * @param {JQuery<HTMLElement>} list the current list of SANs
 * @param {JQuery<HTMLElement>} input the new SAN to add
 */
function AddSAN(list, input) {
    let type = input.find('.san-type');
    let value = input.find('.san-value');
    let spanId = 'SAN' + list.children().length;
    let newSpan = $(`<div id=${spanId}></div>`);
    let newButton = $(`<input type='button' value='✘' onClick="removeSAN('${spanId}')"></input>`);
    let newEntry = $(`<input type='text' name='SANArray' value='${type.val()}: ${value.val()}' class='san-list' readonly></input>`);
    newSpan.append(newButton);
    newSpan.append(newEntry);
    list.append(newSpan);
    type.val('DNS');
    value.val('');
}

/**
 * Removes a SAN from the current list of SANs
 * 
 * @param {JQuery<HTMLElement>} spanId the SAN to remove from the existing SANs list
 */
function removeSAN(spanId) {
    $(`#${spanId}`).remove();
}

/**
 * Initializes the certificates functionality.
 */
function initCerts() {

    $('#generateCertForm').ajaxForm({
        dataType: 'json',
        success: createCACertResponse,
        error: (xhr, _msg, err) => {
            showMessage(xhr.responseJSON);
        }
    });

    $('#newIntermediateForm').ajaxForm({
        dataType: 'json',
        success: createIntermediateCertResponse,
        error: (xhr, _msg, err) => {
            showMessage(xhr.responseJSON);
        }
    });

    $('#newLeafForm').ajaxForm({
        dataType: 'json',
        success: createLeafCertResponse,
        error: (xhr, _msg, err) => {
            showMessage(xhr.responseJSON);
        }
    });

    // Initialize dialogs
    $('#newIntermediate').dialog({
        autoOpen: false,
        //- height: 600,
        width: 350,
        modal: true,
    });

    $('#newLeaf').dialog({
        autoOpen: false,
        //- height: 640,
        width: 400,
        modal: true,
    });


}