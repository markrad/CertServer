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
 * Acquires all of the certificates or keys of a certain type
 * 
 * @param {*} dir string - root | intermediate | leaf | key
 * @returns JSON blob with listing of the requested entries
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

// Builds HTML for a key entry in the UI
function buildKeyEntry(file) {
    let listEntryHTML = ({ id, name }) => `
        <li class="key-line" id="k${id}">
        <span onclick="keyClick('${id}')">
            <span class="key-line-arrow">></span>
            <span class="cert-line-id">
                <span class="cert-line-id-value">${id}</span>
            </span>
            <span class="cert-line-info">
                <span class="cert-line-name">${name}</span>
            </span>
        </span>
        <div class="key-details">
        </div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name });
}

function buildKeyDetail(detail) {
    const detailHTML = ({ id, name, certPair, encrypted }) => `
        <div class="key-container">
        <div class="cert-info-buttons"> 
            <button type="button" class="button2 keyBtnDownload" onClick="keyDownload('${id}')">Download</button>
            <button type="button" class="button2 button2-red keyBtnDelete" onClick="keyDelete('${id}')">Delete</button>
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

function keyHide(details, arrow) {
    details.slideUp(400, () => {
        details.html('');
        arrow.text('>');
    });
}

async function keyShow(details, arrow, id) {
    arrow.text('˅');
    try {
        var result = await lineCache.getKeyDetail(id);
        let content = buildKeyDetail(result);
        details.html(content);
        console.log('success');
        details.slideDown(500);           // &#9650
    }
    catch (err) {
        showError(err.error, err.message);
    };
}

async function keyClick(id) {
    let line = $('.key-line#k' + id);
    let details = line.find('.key-details');
    let arrow = line.find('.key-line-arrow');
    if (details.is(':hidden') == false) {
        keyHide(details, arrow);
    }
    else {
        keyShow(details, arrow, id);
    };
}

/**
 * Download a key from the server
 * 
 * @param {*} id Key id
 */
function keyDownload(id) {
    let filename = $(`#k${id} .cert-line-info`).text() + '.pem';
    let fileLocation = '/api/getKeyPem?id=' + id;
    const anchor = $('<a>', { href: fileLocation, download: filename })[0];
    $('body').append(anchor);
    anchor.click();
    $(anchor).remove();
}

// Call the server to delete a key
function keyDelete(id) {
    let keyName = $(`#k${id} .cert-line-name`).text();
    if (confirm(`This will delete ${keyName}. \n\nDo you wish to continue?`)) {
        $.ajax({
            url: '/deleteKey?id=' + id,
            method: 'DELETE',
            processData: false,
            contentType: false,
            error: (xhr, msg, err) => {
                showError(err, JSON.parse(xhr.responseText).error);
            },
            success: async (_result, _status) => {
                showMessage(`Key ${keyName} deleted`);
            }
        });
    }
}

// Adds certificates to the section passed
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
function buildCertEntry(file) {
    let listEntryHTML = ({ id, name, tags, keyId }) => `
        <li class="cert-line" id="c${id}">
        <span onclick="certClick('${id}')">
            <span class="cert-line-arrow">˃</span>
            <span class="cert-line-id" data-keyid="${keyId}">
                <span class="cert-line-id-value">${id}</span>
            </span>
            <span class="cert-line-info">
                <span class="cert-line-name">${name}</span>
                <span class="cert-line-tags-container">
                    <span class="cert-line-tags-l">[</span>
                    <span class="cert-line-tags-value">${tags}</span>
                    <span class="cert-line-tags-r">]</span>
                </span>
            </span>
        </span>
        <div class="cert-details">
        </div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name, keyId: file.keyId, tags: `${file.tags.join(';')}` });
}

// Build the certificate detail HTML
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
            <span class="cert-info-type-label">Type:&nbsp;</span>
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
            <span class="cert-info-key-label">Key Present:&nbsp;</span>
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

// Hide the certificate detail
function certHide(details, arrow) {
    $('.cert-value-key').removeClass('cert-value-key');
    $('.cert-value-signer').removeClass('cert-value-signer');
    $('.cert-value-signed').removeClass('cert-value-signed');
    details.slideUp(400, () => {
        details.text('');
        arrow.text('>');
    });
}

// Show the certificate detail
async function certShow(id, details, arrow) {
    $('.cert-value-key').removeClass('cert-value-key');
    $('.cert-value-signer').removeClass('cert-value-signer');
    $('.cert-value-signed').removeClass('cert-value-signed');
    arrow.text('˅');
    try {
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
    catch ({ error, message }) {
        showError(error, message);
    }
}

// Shows or hides certificate detail
async function certClick(id) {
    let line = $('.cert-line#c' + id);
    let details = line.find('.cert-details');
    let arrow = line.find('.cert-line-arrow');
    if (details.is(':hidden') == false) {
        certHide(details, arrow);
    }
    else {
        await certShow(id, details, arrow);
    }
}

// Ask the server to delete a certificate
function certDelete(name, id) {
    if (confirm(`This will delete certificate ${name}. \n\nDo you wish to continue?`)) {
        $.ajax({
            url: `/deleteCert?id=${id}`,
            method: 'DELETE',
            processData: false,
            contentType: false,
            error: (xhr, msg, err) => {
                let result = JSON.parse(xhr.responseJSON);
                showError(err, result.error);
            },
            success: async (result, status) => {
                showMessage(`Certificate ${name} deleted`);
            }
        });
    }
}

// Upload a new certificate
function uploadCert(e) {
    var data = new FormData();
    var files = $('#certUpload');
    if (files[0].files.length == 0) {
        alert('No files chosen');
    }
    else {
        for (let i = 0; i < files[0].files.length; i++) {
            data.append('certFile', files[0].files[i]);
        }

        $.ajax({
            url: '/uploadCert',
            method: 'POST',
            processData: false,
            contentType: false,
            data: data,
            error: (xhr, msg, err) => {
                document.getElementById('uploadCertForm').reset();
                showError(err, JSON.parse(xhr.responseText).error);
            },
            success: async (result, status) => {
                document.getElementById('uploadCertForm').reset();
                showMultiMessage(result);
            }
        });
    }
}

function resetTagForm() {
    $('#tagsEdit').dialog('close');
}

function tagsAddLast(tagArray) {
    let lastLine = `
        <span id="tagLast">
            <input class="text ui-widget-content ui-corner-all tags" id="tagValueLast" type="text" name="lastTag" value="">
            </input>
            <input class="tag-form-button" type="button" title="tagEdit" value="✔" onclick="tagAdd('tagArray')"></input>
        </span>`;
    tagArray.append(lastLine);
}
// Open the certificate tags dialog box
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

// Open the new intermediate certificate dialog box
function newIntermediateDialog(id, name) {
    let dialog = $('#newIntermediate');
    dialog.dialog('option', 'title', `${name} -> intermediate`);
    $('#intermediateSigner').val(id); 
    dialog.dialog('open');
}

// Open the new leaf certificate box
function newLeafDialog(id, name) {
    console.log(name);
    let dialog = $('#newLeaf');
    dialog.dialog('option', 'title', `${name} -> leaf`);
    $('#leafSigner').val(id); 
    dialog.dialog('open');
}

// Slide top panes in or out of view
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

// Search tags and hide those that don't match
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

function tagChooserSubmit() {
    console.log('tag submit');
    return false;
}

// Show an informational message box
function showMessage(msg) {
    $('#messageDialogMessage').text(msg);
    $('#messageDialog').dialog({
        title: 'Informational',
        resizable: false,
        maxheight: 260,
        modal: true,
        classes: {
            'ui-dialog': 'ui-state-default'
        },
        buttons: {
            "Ok": function() {
                $('#messageDialogMessage').text('');
                $(this).dialog('close');
            }
        }
    });
}

function showMultiMessage(messages) {
    let msg = $('#messageDialogMessage');
    for (let i in messages) {
        if (messages[i].level == 0) {
            msg.append(`<p class="msg-good-color">${messages[i].message}</p>`);
        }
        else {
            msg.append(`<p class="msg-error-color">${messages[i].message}</p>`);
        }
    }
    $('#messageDialog').dialog({
        title: 'Upload Results',
        resizable: false,
        maxheight: 260,
        maxWidth: 1000,
        modal: true,
        classes: {
            'ui-dialog': 'ui-state-default'
        },
        buttons: {
            "Ok": function() {
                msg.empty();
                $(this).dialog('close');
            }
        }
    });
}

// Show an error message box
function showError(error, message) {
    $('#messageDialogMessage').text(`${error}: ${message}`);
    $('#messageDialog').dialog({
        title: 'Error',
        resizable: false,
        maxheight: 260,
        modal: true,
        classes: {
            'ui-dialog': 'ui-state-error'
        },
        buttons: {
            "Ok": function() {
                $(this).dialog('close');
            }
        }
    });
}

function createCACertResponse(result) {
    $('#generateCAReset').trigger('click');
    showMessage(result.message);
}

function createIntermediateCertResponse(result) {
    $('#generateIntermediateReset').trigger('click');
    showMessage(result.message);
    $('#newIntermediate').dialog('close');
}

function resetIntermediateForm() {
    $('#newIntermediateForm')[0].reset();
    $('#IntermediateSANList').empty();
}

function updateTagsDisplay(result) {
    $('tagsCancelButton').trigger('click');
    showMessage(result.message);
    $('#tagsEdit').dialog('close');
}

function tagDelete(tagIndex) {
    console.log('tagDelete ' + tagIndex);
    $(`#tag${tagIndex}`).remove();
}

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

function createLeafCertResponse(result) {
    $('#generateLeafReset').trigger('click');
    showMessage(result.message);
    $('#newLeaf').dialog('close');
}

function resetLeafForm() {
    $('#newLeafForm')[0].reset();
    $('#LeafSANList').empty();
}

function AddIntermediateSAN() {
    let list = $('#IntermediateSANList');
    let input = $('#IntermediateSANInput');
    AddSAN(list, input);
}

function AddLeafSAN() {
    let list = $('#LeafSANList');
    let input = $('#LeafSANInput');
    AddSAN(list, input);
}

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

function removeSAN(spanId) {
    $(`#${spanId}`).remove();
}


// Called when page is first loaded
$(async function() {
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
                    await keyShow(entry.id, details, arrow);
                }
            }
            else if (detailsVisible) {
                await keyShow(entry.id, details, arrow);
            }
        }
        else {
            $(`${idName} .cert-line-tags-value`).text(`${entry.tags.join(';')}`);
            if (detailsVisible) {
                await certShow(entry.id, details, arrow);
            }
        }
    }

    function addHandler(type, entry) {
        console.log('Add: ' + JSON.stringify(entry));
        let newEntry = type == 4 ? buildKeyEntry(entry) : buildCertEntry(entry);
        let listChildren = $(`#${typeLookup[type]}List li`);
        if (listChildren.length == 1 && listChildren.first().attr('class') == 'empty') {
            listChildren.append(newEntry);
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
        error: (xhr, msg, err) => {
            showError(err, JSON.parse(xhr.responseText).error);
        } 
    });

    $('#newIntermediateForm').ajaxForm({
        dataType: 'json',
        success: createIntermediateCertResponse,
        error: (xhr, msg, err) => {
            showError(err, JSON.parse(xhr.responseText).error);
        } 
    });

    $('#newLeafForm').ajaxForm({
        dataType: 'json',
        success: createLeafCertResponse,
        error: (xhr, msg, err) => {
            showError(err, JSON.parse(xhr.responseText).error);
        } 
    });

    $('#tagsEditForm').ajaxForm({
        datType: 'json',
        success: updateTagsDisplay,
        error: (xhr, msg, err) => {
            showError(err, JSON.parse(xhr.responseText).error);
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
