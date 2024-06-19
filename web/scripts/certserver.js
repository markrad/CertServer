// TODO Clean up this code - WIP

// BUG Tags dialog is flawed if there are no tags

const typeLookup = [
    null,
    'root',
    'intermediate', 
    'leaf',
    'key',
];

var lineCache = null;

/**
 * Adds all the key lines to the UI.
 * 
 * @param {JQuery<HTMLElement>} target the unordered list node for the keys
 * @param {{ id: string, name: string}[]} files List of key entries
 */
// Add all keys to the UI
function buildKeyList(target, files) {
    target.empty();
    if (files.length == 0) {
        target.append('<li class="empty">None</li>');
    }
    else {
        files.sort((l, r) => l.name.localeCompare(r))
            .forEach((file) => {
                target.append(buildKeyEntry(file));
            });
    }
}

/**
 * Builds the HTML for a key entry in the UI
 * 
 * @param {{ id: string, name: string }} file input object containing id and name 
 * @returns {string} HTML string for a key line on the webpage
 */
function buildKeyEntry(file) {
    let listEntryHTML = ({ id, name }) => `
        <li class="key-line" id="k${id}">
            <div class="cert-line-inner" onclick="keyClick('${id}')">
                <span class="key-line-arrow">></span>
                <span class="cert-line-id">${id}</span>
                <span class="cert-line-info">
                    <span class="cert-line-name">${name}</span>
                </span>
            </span>
        </div>
        <div class="key-details" data-id="${id}">
        </div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name });
}

/**
 * Builds a key detail entry for the UI. This detail is shown when the user clicks on a key line.
 * 
 * @param {{name: string, certPair: string, encrypted: 'yes' | 'no'}} detail input object containing id, name, certPair, and encrypted
 * @returns {string} HTML string for a key detail block on the webpage
 */
function buildKeyDetail(detail) {
    const detailHTML = ({ id, name, certPair, encrypted }) => `
        <div class="key-container">
        <div class="cert-info-buttons"> 
            <button type="button" class="button2 keyBtnDownload" onClick="keyDownload('${id}')">Download</button>
            <button type="button" class="button2 button2-red keyBtnDelete" onClick="keyDelete('${name}', '${id}')">Delete</button>
        </div>
        <div class="key-info-type">
            <span class="key-info-name-label">Name:&nbsp;</span>
            <span class="key-info-name-value">${name}</span>
        </div>
        <div class="key-info-pair">
            <span class="key-info-pair-label">Pair:&nbsp;</span>
            <span class="key-info-pair-value">${certPair}</span>
        </div>
        <div class="key-info-encrypted">
            <span class="key-info-encrypted-label">Encrypted:&nbsp;</span>
            <span class="key-info-encrypted-value">${encrypted}</span>
        </div>
    `;
    return detailHTML({ id: detail.id, name: detail.name, certPair: detail.certPair, encrypted: detail.encrypted? 'yes' : 'no' });
}

/**
 * Hides the key detail blob in the UI. This is called when the key line is clicked and the detail is in displayed.
 * 
 * @param {JQuery<HTMLElement>} details jquery object for the key blob
 * @param {JQuery<HTMLElement>} arrow jquery object for the arrow on the key line
 */
function keyHide(details, arrow) {
    details.slideUp(400, () => {
        details.html('');
        arrow.text('>');
    });
}

/**
 * Shows the key detail blob in the UI. This is called when the key line is clicked and the detail is hidden.
 * 
 * @param {JQuery<HTMLElement>} details jquery object for the key blob
 * @param {JQuery<HTMLElement>} arrow jquery object for the arrow on the key line
 */
async function keyShow(details, arrow) {
    arrow.text('˅');
    try {
        let id = details.data('id');
        let result = await lineCache.getKeyDetail(id);
        let content = buildKeyDetail(result);
        details.html(content);
        details.slideDown(500);
    }
    catch (err) {
        showMessage(err);
    };
}

/**
 * Key line click handler. Reverse the display state of the key detail.
 * 
 * @param {string} id 
 */
async function keyClick(id) {
    let line = $('.key-line#k' + id);
    let details = line.find('.key-details');
    let arrow = line.find('.key-line-arrow');
    if (details.is(':hidden') == false) {
        keyHide(details, arrow);
    }
    else {
        keyShow(details, arrow);
    };
}

/**
 * Download a key from the server
 * 
 * @param {string} id Key id
 * @deprecated Can be better done with an href that behaves like a button
 */
function keyDownload(id) {
    // FUTURE Deprecate this
    let filename = $(`#k${id} .cert-line-info`).text() + '.pem';
    let fileLocation = '/api/getKeyPem?id=' + id;
    const anchor = $('<a>', { href: fileLocation, download: filename })[0];
    $('body').append(anchor);
    anchor.click();
    $(anchor).remove();
}

/**
 * Delete a key from the server.
 * 
 * @param {string} name key friendly name
 * @param {string} id key id
 */
async function keyDelete(name, id) {
    try {
        if (confirm(`This will delete key ${name}. \n\nDo you wish to continue?`)) {
            res = await lineCache.deleteKey(id);
            showMessage(res);
        }
    }
    catch (err) {
        showMessage(err);
    }
}

/**
 * Builds a list of certificates and appends it to the target element.
 * 
 * @param {jQuery} target - The target element to append the certificate list to.
 * @param {Array} files - An array of certificate files.
 */
function buildCertList(target, files) {
    target.empty();
    if (files.length == 0)
    {
        target.append('<li class="empty">None</li>');
    }
    else {
        files.sort((l, r) => l.name.localeCompare(r))
            .forEach((file) => {
                target.append(buildCertEntry(file));
        });
    }
}

// Builds HTML for a certificate in the UI
/**
 * 
 * @param {{ id: string, name: string, keyId: string, tags: string[] }} file details for certificate entry line
 * @returns {string} HTML to add to the UI for this certificate
 */
function buildCertEntry(file) {
    let listEntryHTML = ({ id, name, tags, keyId }) => `
        <li class="cert-line" id="c${id}">
            <div class="cert-line-inner" onclick="certClick('${id}')">
                <span class="cert-line-arrow">˃</span>
                <span class="cert-line-id" data-keyid="${keyId}">${id}</span>
                <span class="cert-line-info">
                    <span class="cert-line-name">${name}</span>
                    <span class="cert-line-tags-container">
                        <span class="cert-line-tags-l">[</span>
                        <span class="cert-line-tags-value">${tags}</span>
                        <span class="cert-line-tags-r">]</span>
                    </span>
                </span>
            </div>
            <div class="cert-details" data-id="${id}"></div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name, keyId: file.keyId, tags: `${file.tags.join(';')}` });
}

/**
 * Builds the HTML to display the certificate detail.
 * 
 * @param {{ 
 *          id: string, 
 *          name: string,
 *          certType: 'root' | 'intermediate' | 'leaf',
 *          keyId: string,
 *          serialNumber: string,
 *          fingerprint: string,
 *          fingerprint256: string,
 *          subjectC: string,
 *          subjectST: string,
 *          subjectL: string,
 *          subjectO: string,
 *          subjectOU: string,
 *          subjectCN: string,
 *          issuerC: string,
 *          issuerST: string,
 *          issuerL: string,
 *          issuerO: string,
 *          issuerOU: string,
 *          issuerCN: string,
 *          validFrom: string,
 *          validTo: string,
 *          signer: string,
 *          tags: string
 * }} detail Required elements to build HTML detail
 * @returns {string} HTML to display certificate detail in the UI
 */
function buildCertDetail(detail) {
    let detailHTML = ({
        id,
        name,
        certType,
        withKeyPresent,
        serialNumber,
        fingerprint,
        fingerprint256,
        subjectC,
        subjectST,
        subjectL,
        subjectO,
        subjectOU,
        subjectCN,
        issuerC,
        issuerST,
        issuerL,
        issuerO,
        issuerOU,
        issuerCN,
        validFrom,
        validTo,
        signer,
        keyPresent,
        tags,
    }) => `
        <div class="cert-container">
        <div class="cert-info-buttons"> 
            <a href="/api/getCertificatePem?id=${id}" class="button2 certBtnDownload">Download</a>
            <a href="/api/chainDownload?id=${id}" class="button2 certBtnDownloadChain">Download Chain</a>
            <button type="button" class="button2 button2-red certBtnDelete" onClick="certDelete('${name}', '${id}')">Delete</button>
            <span class="cert-info-optional-buttons">
            <button type="button" class="button2" onClick="newIntermediateDialog('${id}', '${name}')">New Intermediate</button>
            <button type="button" class="button2" onClick="newLeafDialog('${id}', '${name}')">New Leaf</button>
            </span>
        </div>
        <div class="cert-info-type">
            <span class="cert-info-type-label">Type:</span>
            <span class="cert-info-type-value">${certType}</span>
            <span class="cert-info-type-key">${withKeyPresent}</span></div>
            <div class="cert-info-serial">Serial Number: ${serialNumber}</div>  
            <div class="cert-info-fingerprint">FingerPrint: ${fingerprint}</div>
            <div class="cert-info-fingerprint256">FingerPrint256: ${fingerprint256}</div>
            <div class="cert-info-subject">Subject:
            <span class="cert-info-subject-c">C=${subjectC};</span>
            <span class="cert-info-subject-st">ST=${subjectST};</span>
            <span class="cert-info-subject-l">L=${subjectL};</span>
            <span class="cert-info-subject-o">O=${subjectO};</span>
            <span class="cert-info-subject-ou">OU=${subjectOU};</span>
            <span class="cert-info-subject-cn">CN=${subjectCN}</span>
        </div>
        <div class="cert-info-issuer">&nbsp;Issuer:
            <span class="cert-info-issuer-c">C=${issuerC};</span>
            <span class="cert-info-issuer-st">ST=${issuerST};</span>
            <span class="cert-info-issuer-l">L=${issuerL};</span>
            <span class="cert-info-issuer-o">O=${issuerO};</span>
            <span class="cert-info-issuer-ou">OU=${issuerOU};</span>
            <span class="cert-info-issuer-cn">CN=${issuerCN}</span>
        </div>
        <div class="cert-info-valid-from">Valid from: ${validFrom}</div>
        <div class="cert-info-valid-to">Valid to: ${validTo}</div>
        <div class="cert-info-signer">
            <span class="cert-info-signer-label">Signed by:&nbsp;</span>
            <span class="cert-info-signer-value">${signer}</span>
        </div>
        <div class="cert-info-key">
            <span class="cert-info-key-label">Key Present:</span>
            <span class="cert-info-key-value">${keyPresent}</span> 
        </div>
        <div class="cert-info-tags">
            <span class="cert-info-tags-label">Tags: [</span>
            <span class="cert-info-tags-value">${tags}</span>
            <span class="cert-info-tags-end">]</span>
            <button class="cert-info-tags-edit" onClick=tagsEdit('c${id}')>🖉</button>
        </div>
        </div>
    `;
    return detailHTML({
        id: detail.id,
        name: detail.name,
        certType: detail.certType,
        withKeyPresent: detail.keyId != null? ' with private key' : '',
        serialNumber: detail.serialNumber,
        fingerprint: detail.fingerprint,
        fingerprint256: detail.fingerprint256,
        subjectC: detail.subject.C,
        subjectST: detail.subject.ST,
        subjectL: detail.subject.L,
        subjectO: detail.subject.O,
        subjectOU: detail.subject.OU,
        subjectCN: detail.subject.CN,
        issuerC: detail.issuer.C,
        issuerST: detail.issuer.ST,
        issuerL: detail.issuer.L,
        issuerO: detail.issuer.O,
        issuerOU: detail.issuer.OU,
        issuerCN: detail.issuer.CN,
        validFrom: detail.validFrom,
        validTo: detail.validTo,
        signer: detail.signer,
        keyPresent: detail.keyId != null? 'yes' : 'no',
        tags: detail.tags.length != 0? detail.tags.join(';') : '',
    });
}

/**
 * Remove the highlights that signify a key or certificate is related to the certificate that has had the detail displayed.
 */
function removeRelativeHighlights() {
    $('.cert-value-key').removeClass('cert-value-key');
    $('.cert-value-signer').removeClass('cert-value-signer');
    $('.cert-value-signed').removeClass('cert-value-signed');
}

/**
 * Hides the certificate detail.
 * 
 * @param {JQuery<HTMLElement>} details certificate details blob
 * @param {JQuery<HTMLElement>} arrow arrow node in overview line
 */
function certHide(details, arrow) {
    removeRelativeHighlights();
    details.slideUp(400, () => {
        details.text('');
        arrow.text('>');
    });
}

/**
 * Shows the certificate detail.
 * 
 * @param {JQuery<HTMLElement>} details certificate details blob
 * @param {JQuery<HTMLElement>} arrow arrow node in overview line
 */
async function certShow(details, arrow) {
    removeRelativeHighlights();
    arrow.text('˅');
    try {
        let id = details.data('id');
        var result = await lineCache.getCertDetail(id);
        let content = buildCertDetail(result);
        details.html(content);
        if (result.certType == 'root') details.find('.' + 'certBtnDownloadChain').hide();
        if (result.keyId == null || result.certType == 'leaf') details.find('.' + 'cert-info-optional-buttons').hide();
        [
            [result.subject.C, 'cert-info-subject-c'],
            [result.subject.ST, 'cert-info-subject-st'],
            [result.subject.L, 'cert-info-subject-l'],
            [result.subject.O, 'cert-info-subject-o'],
            [result.subject.OU, 'cert-info-subject-ou'],
            [result.subject.CN, 'cert-info-subject-cn'],
            [result.issuer.C, 'cert-info-issuer-c'],
            [result.issuer.ST, 'cert-info-issuer-st'],
            [result.issuer.L, 'cert-info-issuer-l'],
            [result.issuer.O, 'cert-info-issuer-o'],
            [result.issuer.OU, 'cert-info-issuer-ou'],
            [result.issuer.CN, 'cert-info-issuer-cn'],
            [result.signed, 'cert-info-signer'], 
        ].forEach((entry) => {
            if (entry[0] == null) {
                let t = details.find('.' + entry[1]);
                t.hide();
            }
        });

        let now = new Date();

        if (new Date(result.validTo) < now) {
            details.find('.cert-info-valid-to').addClass('cert-out-of-validity');
        }

        if (new Date(result.validFrom) > now) {
            details.find('.cert-info-valid-from').addClass('cert-out-of-validity');
        }

        details.slideDown(500);

        $(`#k${result.keyId}`).find('.cert-line-info').addClass('cert-value-key');
        $(`#c${result.signerId}`).find('.cert-line-info').addClass('cert-value-signer');
        result.signed.forEach((s) => $(`#c${s}`).find('.cert-line-info').addClass('cert-value-signed'));
    }
    catch (err) {
        showMessage(err);
    }
}

/**
 * Certificate line click handler.
 * 
 * @param {string} id certificate id that was clicked 
 */
async function certClick(id) {
    let line = $('.cert-line#c' + id);
    let details = line.find('.cert-details');
    let arrow = line.find('.cert-line-arrow');
    if (details.is(':hidden') == false) {
        certHide(details, arrow);
    }
    else {
        await certShow(details, arrow);
    }
}

/**
 * Sends a request to the server to delete a certificate.
 * 
 * @param {string} name name of the certificate for display purposes
 * @param {string} id id of the certificate to be deleted
 */
async function certDelete(name, id) {
    try {
        if (confirm(`This will delete certificate ${name}. \n\nDo you wish to continue?`)) {
            let res = await lineCache.deleteCert(id);
            showMessage(res);
        }
    }
    catch (err) {
        showMessage(err);
    }
}

async function dropHandler(event) {
    event.preventDefault();
    var files = event.dataTransfer.files;
    var data = new FormData();
    for (let file of files) {
        data.append('certFile', file);
    }
    let result = await lineCache.postToServer('/uploadPem', data);
    showMessage(result);
}

function dragOverHandler(event) {
    event.preventDefault();
}
/**
 * Upload a new pem file to the server. This can be a certificate, a key, or a file containing multiple pem files.
 * 
 */
async function uploadPem(x) {
    var data = new FormData();
    var files = $('#certUpload');
    if (files[0].files.length == 0) {
        alert('No files chosen');
    }
    else {
        for (let i = 0; i < files[0].files.length; i++) {
            data.append('certFile', files[0].files[i]);
        }
        try {
            let result = await lineCache.postToServer('/uploadPem', data);
            showMessage(result);
        }
        catch (err) {
            document.getElementById('uploadCertForm').reset();
            showMessage(err);
        }
    }
}

/**
 * Close the tags form
 */
function resetTagForm() {
    $('#tagsEdit').dialog('close');
}

/**
 * Appends a new input tag box to the end of the tags array.
 * 
 * @param {JQuery<HTMLElement} tagArray the array of existing tags
 */
function tagsAddLast(tagArray) {
    let lastLine = `
        <span id="tagLast">
            <input class="text ui-widget-content ui-corner-all tags" id="tagValueLast" type="text" name="lastTag" value="">
            </input>
            <input class="tag-form-button" type="button" title="tagEdit" value="✔" onclick="tagAdd('tagArray')"></input>
        </span>`;
    tagArray.append(lastLine);
}

/**
 * Builds the tags dialog with the existing tags in separate inputs that can be edited or deleted.
 * 
 * @param {string} id certificate id of the tags to be edited
 */
function tagsEdit(id) {
    let line = ({ tagValue, tagIndex }) => `
        <span id="tag${tagIndex}">
            <input class="text ui-widget-content ui-corner-all tags" id="tagValue${tagIndex}"type="text" name="tags" value="${tagValue}">
            </input>
            <input class="tag-form-button" type="button" title="tagEdit" value="✘" onclick="tagDelete('${tagIndex}')">
        </span>`;

    let entry = $('#' + id);
    let dialog = $('#tagsEdit');
    $('#certificateId').val(id.substring(1));
    let tagArray = $('#tagArray');
    tagArray.empty();
    let tags = entry.find('.cert-info-tags-value').text().split(';');
    if (tags[0] != '') {
        for (let tagI in tags) {
            let newInput = line({ tagValue: `${tags[tagI]}`, tagIndex: `${tagI.toString().padStart(3, '0')}` });
            tagArray.append(newInput);
        }
    }
    tagsAddLast(tagArray);
    tagArray.data('highValue', tags.length.toString());
    dialog.dialog('open');
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
 * Open a new leaf certificate dialog box.
 * 
 * @param {string} id id of the certificate that will sign this new leaf 
 * @param {*} name name of the certificate that will sign this new leaf
 */
function newLeafDialog(id, name) {
    let dialog = $('#newLeaf');
    dialog.dialog('option', 'title', `${name} -> leaf`);
    $('#leafSigner').val(id); 
    dialog.dialog('open');
}

// Slide top panes in or out of view
/**
 * Toggles the top forms in and out of view
 * 
 * @param {JQuery<HTMLElement} button the button that was clicked indicating the form to show unless it is already showing then it will be hidden
 * @param {string} id html id of the form to display or hide
 */
function togglePane(button, id) {
    let arrow = button.find('.button1-arrow');
    let p = $(id);
    if (p.is(':visible')) {
        arrow.text('>');
        p.slideUp(500);
    }
    else {
        $('.top-slide').each(function(_i, form) {
            if (`#${form.id}` != id) {
                arrow.text('˅')
                $(form).slideUp(500);
            }
        });
        p.slideDown(500);
    }
}

/**
 * Searches for certificates that contain a string in the tags that matches the input filter. Hides any lines that don't.
 */
function searchTags() {
    let filter = $('#tagChooserValue').val();
    let keyIds = [];
    let r = new RegExp(filter, $('#tagCaseLabelCBox').is(':checked')? 'i' : '');
    $('.cert-line').each((i, line) => {
        let tags = $(line).find('.cert-line-tags-value');
        if (filter.length > 0 && r.exec(tags.text()) == null) {
            $(line).hide();
            let details = $(line).find('.cert-details');
            let arrow = $(line).find('.cert-line-arrow');
            certHide(details, arrow);
        }
        else {
            $(line).show();
            let keyId = $(line).find('.cert-line-id').data('keyid');
            if (keyId != null) {
                keyIds.push(keyId);
            }
        }
    });
    $('.key-line').each((i, line) => {
        if (keyIds.includes(parseInt($(line).attr('id').slice(1)))) {
            $(line).show();
        }
        else {
            $(line).hide();
            let details = $(line).find('.key-details');
            let arrow = $(line).find('key-line-arrow');
            keyHide(details, arrow);
        }
    });
}

/**
 * Work in progress function to try and improve the tag dialog behavior.
 * 
 * @returns {boolean} always false
 */
function tagChooserSubmit() {
    console.log('tag submit');
    return false;
}

/**
 * Displays a modeless dialog with an informational message which fades out after 3 seconds
 * 
 * @param {string} msg message to display
 */
function showMessage(result) {
    let timerHandle = null;
    let msg = $('#messageDialogMessage');
    let msgLine = '';
    let first = true;
    for (let m of result.messages) {
        if (m.type == 0) {
            msg.append(`<p class="msg-good-color ${msgLine}">${m.message}</p>`);
        }
        else {
            msg.append(`<p class="msg-error-color ${msgLine}">${m.message}</p>`);
        }

        if (first) {
            msgLine = 'msg-line';
            first = false;
        }
    }
    // $('#messageDialogMessage').text(msg);
    $('#messageDialog').dialog({
        title: result.title,
        resizable: false,
        maxheight: 260,
        modal: !result.success,
        show: ('fade', 700),
        hide: ('fade', 700),
        classes: {
            'ui-dialog': result.success? 'ui-state-default' : 'ui-state-error'
        },
        buttons: {
            "Ok": function() {
                $('#messageDialogMessage').text('');
                $(this).dialog('close');
                if (timerHandle) {
                    clearTimeout(timerHandle);
                    timerHandle = null;
                }
            }
        }
    });
    if (result.success) {
        timerHandle = setTimeout(() => {
            $('#messageDialog').dialog('close');
            $('#messageDialogMessage').text('');
        }, 3000);
    }
}
function onGenerateCert(event) {
    event.preventDefault();
    let frm = $('#generateCertForm');
    $.ajax({
        type: frm.attr('method'),
        url: frm.attr('action'),
        headers: { 'Authorization': `Bearer ${sessionStorage.getItem('token')}` },
        data: frm.serialize(),
        success: createCACertResponse,
        error: function(data) {
            showMessage(data.responseJSON);
        }
    });
}
/**
 * Called when a new CA is successfully created.
 * 
 * @param {{ message: string }} result result when creating a new CA
 */
function createCACertResponse(result) {
    $('#generateCAReset').trigger('click');
    showMessage(result);
}
function onCreateIntermediateCert(event) {
    event.preventDefault();
    let frm = $('#newIntermediateForm');
    $.ajax({
        type: frm.attr('method'),
        url: frm.attr('action'),
        headers: { 'Authorization': `Bearer ${sessionStorage.getItem('token')}` },
        data: frm.serialize(),
        success: createIntermediateCertResponse,
        error: function(data) {
            showMessage(data.responseJSON);
        }
    });
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
function onCreateLeafCert(event) {
    event.preventDefault();
    let frm = $('#newLeafForm');
    $.ajax({
        type: frm.attr('method'),
        url: frm.attr('action'),
        headers: { 'Authorization': `Bearer ${sessionStorage.getItem('token')}` },
        data: frm.serialize(),
        success: createLeafCertResponse,
        error: function(data) {
            showMessage(data.responseJSON);
        }
    });
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
 * Called when the certificate's tags are successfully updated.
 * 
 * @param {{ message: string }} result the result message
 */
function updateTagsDisplay(result) {
    $('tagsCancelButton').trigger('click');
    showMessage(result);
    $('#tagsEdit').dialog('close');
}

/**
 * Called to remove a tag from the certificates tags.
 * 
 * @param {number} tagIndex index of the tag to remove
 */
function tagDelete(tagIndex) {
    $(`#tag${tagIndex}`).remove();
}

/**
 * Adds the new tag input to the list of tags.
 * 
 * @param {string} tagArrayId HTML id of the tag array
 */
function tagAdd(tagArrayId) {
    let tagArray = $(`#${tagArrayId}`);
    let tagLast = tagArray.find('#tagLast');
    let highValue = parseInt(tagArray.data('highValue'));
    let id = highValue.toString().padStart(3, '0');
    let tagInput = tagLast.find('#tagValueLast');
    let tagButton = tagLast.find('.tag-form-button');
    tagLast.prop('id', 'tag' + id);
    tagInput.prop('name', 'tags');
    tagInput.prop('id', 'tagValue' + id);
    tagButton.val('✘');
    tagButton.attr('onclick', `tagDelete('${id}')`);
    tagsAddLast(tagArray);
    tagArray.data('highValue', `${(++highValue)}`);
}

/**
 * This function is automatically called by jQuery when the webpage is loaded. It initializes stuff.
 */
$(async function() {

    // May have been redirected to the sign in page
    if (window.location.pathname != '/') {
        return;
    }

    let calcRefresh = () => {
        let expiresAt = sessionStorage.getItem('expiresAt');
        if (expiresAt == null) {
            return;
        }
        let expiresIn = Number(expiresAt) - (Date.now() / 1000);
        let diff = expiresIn - 60;
        console.log(`${new Date()} Refresh in ${diff} seconds`);
        setTimeout(() => {
            $.ajax({
                type: 'POST',
                url: '/api/tokenrefresh',
                headers: {
                    "Authorization": `Bearer ${sessionStorage.getItem('token')}`
                },
                error: (xhr, _msg, err) => {
                    console.error(xhr);
                },
                success: (data) => {
                    if (data.success == true) {
                        sessionStorage.setItem('token', data.token);
                        sessionStorage.setItem('expiresAt', data.expiresAt);
                        calcRefresh();
                        console.log(`${new Date()} Token refreshed`);
                    }
                }
            });
        }, diff * 1000);
    }
    // Check the token time to live
    calcRefresh();

    // Initialize date input boxes
    let datePicker;
    datePicker = $('#CAValidFrom');
    datePicker.datepicker( { minDate: -20, defaultDate: 0 } );
    datePicker = $('#CAValidTo');
    datePicker.datepicker( { defaultDate: +365 } );
    datePicker = $('#IntermediateValidFrom');
    datePicker.datepicker( { minDate: -20, defaultDate: 0 } );
    datePicker = $('#IntermediateValidTo');
    datePicker.datepicker( { defaultDate: +365 } );
    datePicker = $('#LeafValidFrom');
    datePicker.datepicker( { minDate: -20, defaultDate: 0 } );
    datePicker = $('#LeafValidTo');
    datePicker.datepicker( { defaultDate: +365 } );

    lineCache = new LineCache();

    lineCache.setAddHandler(addHandler);
    lineCache.setUpdateHandler(updateHandler);
    lineCache.setDeleteHandler(deleteHandler);
        
    /**
     * Applies an update from the server to the UI.
     * 
     * @param {1 | 2 | 3 | 4} type Type of entry updated - root, intermediate, leaf, or key (1, 2, 3, 4)
     * @param {{ id: number, name: string }} entry id and name of the entry - id will never change, name can
     */
    async function updateHandler(type, entry) {
        console.log('Update: ' + JSON.stringify(entry));
        let idName = `${type == 4 ? '#k' : '#c'}${entry.id}`;
        let name = $(`${idName} .cert-line-name`);
        let details = $(`${idName} ${type == 4? '.key-details' : '.cert-details'}`);
        let arrow = $(`${idName}  ${type == 4 ? '.key-line-arrow' : '.cert-line-arrow'}`);
        let detailsVisible = !details.is(':hidden')
        if (type == 4) {
            if (entry.name != name) {
                deleteHandler(type, entry.id);
                addHandler(type, entry);
                if (detailsVisible) {
                    await keyShow(details, arrow);
                }
            }
            else if (detailsVisible) {
                await keyShow(details, arrow);
            }
        }
        else {
            $(`${idName} .cert-line-tags-value`).text(`${entry.tags.join(';')}`);
            if (detailsVisible) {
                await certShow(details, arrow);
            }
        }
    }

    /**
     * Add a new entry from the server to the UI.
     * 
     * @param {1 | 2 | 3 | 4} type Type of entry updated - root, intermediate, leaf, or key (1, 2, 3, 4)
     * @param {{ id: number, name: string }} entry id and name of the entry - id will never change, name can
     */
    function addHandler(type, entry) {
        console.log('Add: ' + JSON.stringify(entry));
        let newEntry = type == 4 ? buildKeyEntry(entry) : buildCertEntry(entry);
        let listChildren = $(`#${typeLookup[type]}List li`);
        if (listChildren.length == 1 && listChildren.first().attr('class') == 'empty') {
            listChildren.last().after(newEntry);
            listChildren.first().remove();
        }
        else {
            if (entry.name.localeCompare(listChildren.last().find('span.cert-line-name').text()) == 1) {
                listChildren.last().after(newEntry);
            }
            else {
                for (let i = 0; i < listChildren.length; i++) {
                    console.log(`>> ${entry.name} ${$(listChildren[i]).find('span.cert-line-name').text() }`)
                    if (entry.name.localeCompare($(listChildren[i]).find('span.cert-line-name').text()) != 1) {
                        $(listChildren[i]).before(newEntry);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Removes an entry deleted by the server.
     * 
     * @param {1 | 2 | 3 | 4} type Type of entry updated - root, intermediate, leaf, or key (1, 2, 3, 4)
     * @param {*} id id of deleted entry
     */
    function deleteHandler(type, id) {
        console.log('Delete: ' + id);
        let entry = $(`#${type == 4 ? 'k' : 'c'}${id}`);
        let list = entry.closest('ul');
        $(`#${type == 4 ? 'k' : 'c'}${id}`).remove();
        if (list.children().length == 0) {
            list.append('<li class="empty">None</li>');
        }
    }

    // Populate the page
    let files;
    [
        ['root', buildCertList],
        ['intermediate', buildCertList],
        ['leaf', buildCertList],
        ['key', buildKeyList]
    ].forEach(async (entry) => {
        files = await lineCache.getLineHeaders(entry[0]);
        entry[1]($(`#${entry[0]}List`), files);
    });

    $('#generateCertForm').ajaxForm({
        dataType: 'json',
        success: createCACertResponse,
        error: (xhr, _msg, err) => {
            showMessage(JSON.parse(xhr.responseText));
        } 
    });

    $('#newIntermediateForm').ajaxForm({
        dataType: 'json',
        success: createIntermediateCertResponse,
        error: (xhr, _msg, err) => {
            showMessage(JSON.parse(xhr.responseText));
        } 
    });

    $('#newLeafForm').ajaxForm({
        dataType: 'json',
        success: createLeafCertResponse,
        error: (xhr, _msg, err) => {
            showMessage(JSON.parse(xhr.responseText));
        } 
    });

    $('#tagsEditForm').ajaxForm({
        datType: 'json',
        success: updateTagsDisplay,
        error: (xhr, _msg, err) => {
            showMessage(xhr.responseText);
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
    
    $('#tagsEdit').dialog({
        autoOpen: false,
        modal: true,
        width: 450,
    });
});
