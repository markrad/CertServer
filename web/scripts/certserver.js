// TODO Clean up this code

const typeLookup = [
    '',
    'root',
    'intermediate', 
    'leaf',
    'key',
]

// Acquires all of the certificates or keys of a certain type
// dir: string - root | intermediate | leaf | key
//
// Returns JSON blob with listing of the requested entries
async function getDir(dir) {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: `/certList?type=${dir}`,
            method: 'GET',
            error: (_xhr, _status, err) => { 
                console.error('Failed to get ' + dir);
                reject(err);
            },
            success: (result, _status, _xhr) => {
                resolve(result);
            }
        });
    });
}

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
        <li class="keyLine" id="k${id}">
        <span onclick="keyClick('${id}')">
            <span class="keyArrow">></span>
            <span class="idLine">
                <span class="idValue">${id}</span>
            </span>
            <span class="certValue">
                <span class="certName">${name}</span>
            </span>
        </span>
        <div class="keyDetails">
        </div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name });
}

function buildKeyDetail(detail) {
    const detailHTML = ({ id, name, certPair, encrypted }) => `
        <div class="keyInfo">
        <div class="certInfoButtons"> 
            <button type="button" class="button2 keyBtnDownload" onClick="keyDownload('${id}')">Download</button>
            <button type="button" class="button2 button2Red keyBtnDelete" onClick="keyDelete('${id}')">Delete</button>
        </div>
        <div class="keyName">
            <span class="keyNameLabel">Name:&nbsp;</span>
            <span class="keyNameValue">${name}</span>
        </div>
        <div class="keyPair">
            <span class="keyPairLabel">Pair:&nbsp;</span>
            <span class="keyPairValue">${certPair}</span>
        </div>
        <div class="keyEncrypted">
            <span class="keyEncryptedLabel">Encrypted:&nbsp;</span>
            <span class="keyEncryptedValue">${encrypted}</span>
        </div>
    `;
    return detailHTML({ id: detail.id, name: detail.name, certPair: detail.certPair, encrypted: result.encrypted? 'yes' : 'no' });
}

async function keyClick(id) {
    let line = $('.keyLine#k' + id);
    let details = line.find('.keyDetails');
    let arrow = line.find('.keyArrow');
    if (details.is(':hidden') == false) {
        details.slideUp(400, () => {
            details.html('');
            arrow.text('>');
        });
    }
    else {
        arrow.text('˅');
        try {
            result = await getKeyDetails({ id: id });
            let content = buildKeyDetail(result);
            details.html(content);
            console.log('success');
            details.slideDown(500);           // &#9650
        }
        catch (err) {
            showError(err.error, err.message);
        };
    };
}

// Get key details from the server
async function getKeyDetails({ id }) {
    return new Promise((resolve, reject) => {
        let url = `/keyDetails?id=${id}`;
        $.ajax({
            url: url,
            method: 'GET',
            processData: false,
            contentType: false,
            error: (xhr, msg, err) => {
                reject({ error: err, message: xhr.responseText });
            },
            success: (result, status) => {
                resolve(result);
            }
        });
    });
}

// Call the server to download the key
function keyDownload(id) {
    let filename = $(`#k${id} .certValue`).text() + '.pem';
    let fileLocation = '/api/getKeyPem?id=' + id;
    const anchor = $('<a>', { href: fileLocation, download: filename })[0];
    $('body').append(anchor);
    anchor.click();
    $(anchor).remove();
}

// Call the server to delete a key
function keyDelete(id) {
    let keyName = $(`#k${id} .certValue`).text();
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

// Upload a new key
function uploadKey(e) {
    var data = new FormData();
    var files = $('#keyUpload');
    if (files[0].files.length == 0) {
        alert('No files chosen');
    }
    else {
        for (let i = 0; i < files[0].files.length; i++) {
            data.append('keyFile', files[0].files[i]);
        }

        let url = `/uploadKey${$('#keyPasswordValue').val() == '' ? '' : `?password=${$('#keyPasswordValue').val()}`}`;

        $.ajax({
            url: url,
            method: 'POST',
            processData: false,
            contentType: false,
            data: data,
            error: (xhr, _msg, err) => {
                document.getElementById('uploadKeyForm').reset();
                showError(err, JSON.parse(xhr.responseText).error);
            },
            success: async (_result, _status) => {
                document.getElementById('uploadKeyForm').reset();
                showMessage('Key uploaded');
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
    let listEntryHTML = ({ id, name, tags }) => `
        <li class="certLine" id="c${id}">
        <span onclick="certClick('${id}')">
            <span class="certArrow">˃</span>
            <span class="idLine">
                <span class="idValue">${id}</span>
            </span>
            <span class="certValue">
                <span class="certName">${name}</span>
                <span class="CertTagsOuter">
                    <span class="certTagsL">[</span>
                    <span class="certTags">${tags}</span>
                    <span class="certTagsR">]</span>
                </span>
            </span>
        </span>
        <div class="certDetails">
        </div>
        </li>
    `;
    return listEntryHTML({ id: file.id, name: file.name, tags: `${file.tags.join(';')}` });
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
        <div class="certInfo">
        <div class="certInfoButtons"> 
            <a href="/api/getCertificatePem?id=${id}" class="button2 certBtnDownload">Download</a>
            <a href="/api/chainDownload?id=${id}" class="button2 certBtnDownloadChain">Download Chain</a>
            <button type="button" class="button2 button2Red certBtnDelete" onClick="certDelete('${name}', '${id}')">Delete</button>
            <span class="certOptionalButtons">
            <button type="button" class="button2" onClick="newIntermediateDialog('${id}', '${name}')">New Intermediate</button>
            <button type="button" class="button2" onClick="newLeafDialog('${id}', '${name}')">New Leaf</button>
            </span>
        </div>
        <div class="certInfoType">
            <span class="certTypeLabel">Type:&nbsp;</span>
            <span class="certTypeValue">${certType}</span>
            <span class="certPrivateKey">${withKeyPresent}</span></div>
        <div class="certInfoSerial">Serial Number: ${serialNumber}</div>  
        <div class="certFingerprint">FingerPrint: ${fingerprint}</div>
        <div class="certFingerprint256">FingerPrint256: ${fingerprint256}</div>
        <div class="certInfoSubject">Subject:&nbsp;
            <span class="certInfoSubjectC">C=${subjectC};&nbsp;</span>
            <span class="certInfoSubjectST">ST=${subjectST};&nbsp;</span>
            <span class="certInfoSubjectL">L=${subjectL};&nbsp;</span>
            <span class="certInfoSubjectO">O=${subjectO};&nbsp;</span>
            <span class="certInfoSubjectOU">OU=${subjectOU}; </span>
            <span class="certInfoSubjectCN">CN=${subjectCN}</span>
        </div>
        <div class="certInfoIssuer">&nbsp;Issuer:&nbsp;
            <span class="certInfoIssuerC">C=${issuerC};&nbsp;</span>
            <span class="certInfoIssuerST">ST=${issuerST};&nbsp;</span>
            <span class="certInfoIssuerL">L=${issuerL};&nbsp;</span>
            <span class="certInfoIssuerO">O=${issuerO};&nbsp;</span>
            <span class="certInfoIssuerOU">OU=${issuerOU};&nbsp;</span>
            <span class="certInfoIssuerCN">CN=${issuerCN}</span>
        </div>
        <div class="certInfoFrom">Valid from: ${validFrom}</div>
        <div class="certInfoTo">Valid to: ${validTo}</div>
        <div class="certInfoSigner">
            <span class="certInfoSignerLabel">Signed by:&nbsp;</span>
            <span class="certInfoSignerValue">${signer}</span>
        </div>
        <div class="certInfoKey">
            <span class="certInfoKeyLabel">Key Present:&nbsp;</span>
            <span class="certInfoKeyValue">${keyPresent}</span> 
        </div>
        <div class="CertTags">
            <span class="certTagsLabel">Tags: [</span>
            <span class="certTagsValue">${tags}</span>
            <span class="certTagsEnd">]</span>
            <button class="certTagsEdit" onClick=tagsEdit('c${id}')>🖉</button>
        </div>
        </div>
    `;
    return detailHTML({
        id: detail.id,
        name: detail.name,
        certType: detail.certType,
        withKeyPresent: detail.keyPresent == 'yes'? ' with private key' : '',
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
        keyPresent: detail.keyPresent,
        tags: detail.tags.length != 0? detail.tags.join(';') : '',
    });
}

// Hide the certificate detail
function certHide(details, arrow) {
    $('.certValueKey').removeClass('certValueKey');
    $('.certValueSigner').removeClass('certValueSigner');
    $('.certValueSigned').removeClass('certValueSigned');
    details.slideUp(400, () => {
        details.text('');
        arrow.text('>');
    });
}

// Show the certificate detail
async function certShow(id, details, arrow) {
    $('.certValueKey').removeClass('certValueKey');
    $('.certValueSigner').removeClass('certValueSigner');
    $('.certValueSigned').removeClass('certValueSigned');
    arrow.text('˅');
    try {
        var result = await getCertDetails({ id: id});
        let content = buildCertDetail(result);
        details.html(content);
        if (result.certType == 'root') details.find('.' + 'certBtnDownloadChain').hide();
        if (result.keyPresent == 'no' || result.certType == 'leaf') details.find('.' + 'certOptionalButtons').hide();
        [
            [result.subject.C, 'certInfoSubjectC'],
            [result.subject.ST, 'certInfoSubjectST'],
            [result.subject.L, 'certInfoSubjectL'],
            [result.subject.O, 'certInfoSubjectO'],
            [result.subject.OU, 'certInfoSubjectOU'],
            [result.subject.CN, 'certInfoSubjectCN'],
            [result.issuer.C, 'certInfoIssuerC'],
            [result.issuer.ST, 'certInfoIssuerST'],
            [result.issuer.L, 'certInfoIssuerL'],
            [result.issuer.O, 'certInfoIssuerO'],
            [result.issuer.OU, 'certInfoIssuerOU'],
            [result.issuer.CN, 'certInfoIssuerCN'],
            [result.signed, 'certInfoSigner'], 
        ].forEach((entry) => {
            if (entry[0] == null) {
                let t = details.find('.' + entry[1]);
                t.hide();
            }
        });

        let now = new Date();

        if (new Date(result.validTo) < now) {
            details.find('.certInfoTo').addClass('certOutOfValidity');
        }

        if (new Date(result.validFrom) > now) {
            details.find('.certInfoFrom').addClass('certOutOfValidity');
        }

        details.slideDown(500);

        $(`#k${result.keyId}`).find('.certValue').addClass('certValueKey');
        $(`#c${result.signerId}`).find('.certValue').addClass('certValueSigner');
        result.signed.forEach((s) => $(`#c${s}`).find('.certValue').addClass('certValueSigned'));
    }
    catch ({ error, message }) {
        showError(error, message);
    }
}

// Shows or hides certificate detail
async function certClick(id) {
    let line = $('.certLine#c' + id);
    let details = line.find('.certDetails');
    let arrow = line.find('.certArrow');
    if (details.is(':hidden') == false) {
        certHide(details, arrow);
    }
    else {
        await certShow(id, details, arrow);
    }
}

// Get certificate details from the server
async function getCertDetails({ id }) {
    return new Promise(async (resolve, reject) => {
        try {
            let url = `/certDetails?id=${id}`;
            $.ajax({
                url: url,
                method: 'GET',
                processData: false,
                contentType: false,
                error: (xhr, msg, err) => {
                    reject({ error: err, message: xhr.responseText});
                },
                success: (result, status) => {
                    resolve(result);
                }
            });
        }
        catch (err) {
            reject({ error: err, message: 'Unknown error' });
        }       
    });
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
                showMessage('File uploaded');
            }
        });
    }
}

// Get the certificate name (CN) from the id
async function getName(type, id) {
    return new Promise((resolve, reject) => {
        let url = type == 4? '/api/keyname' : '/api/certname';
        url += '?id=' + id.toString();
        $.ajax({
            url: url,
            method: 'GET',
            processData: false,
            contentType: false,
            error: (xhr, msg, err) => {
                reject(err);
            },
            success: async (result, status) => {
                resolve(result);
            }
        });
    });
}

// Open the certificate tags dialog box
function tagsEdit(id) {
    let entry = $('#' + id);
    let dialog = $('#tagsEdit');
    $('#certificateId').val(id.substring(1));
    $('#tags').val(entry.find('.certTagsValue').text());
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
function togglePane(id) {
    // FUTURE Add chevrons
    let p = $(id);
    if (p.is(':visible')) {
        p.slideUp(500);
    }
    else {
        $('.topSlide').each(function(_i, form) {
            if (`#${form.id}` != id) $(form).slideUp(500);
        });
        p.slideDown(500);
    }
}

// Search tags and hide those that don't match
function searchTags() {
    let filter = $('#tagChooserValue');
    let lines = $('.certLine');
    $('.certLine').each((i, line) => {
        let tags = $(line).find('.certTags');
        if (tags.text().match(filter.val()) == null) {
            $(line).hide();
            let details = $(line).find('.certDetails');
            let arrow = $(line).find('.certArrow');
            certHide(details, arrow);
        }
        else {
            $(line).show();
        }
    });
}

// Show an informational message box
function showMessage(msg) {
    $.magnificPopup.open({
        items: {
            src: `<div class="white-popup">${msg}</div>`,
            type: 'inline'
        }
    });
}

// Show an error message box
function showError(error, message) {
    $.magnificPopup.open({
        items: {
            src: `<div class="error-popup">${error}: ${message}</div>`,
            type: 'inline'
        }
    });
}

function createCACertResponse(result) {
    // BUG click issue
    $('#generateCAReset').click();
    showMessage(result.message);
}

function createIntermediateCertResponse(result) {
    // BUG click issue
    $('#generateIntermediateReset').click();
    showMessage(result.message);
    $('#newIntermediate').dialog('close');
}

function resetIntermediateForm() {
    $('#newIntermediateForm')[0].reset();
    $('#IntermediateSANList').empty();
}

function updateTagsDisplay(result) {
    // BUG click issue
    $('tagsCancelButton').click();
    showMessage(result.message);
    $('#tagsEdit').dialog('close');
}

function tagsCancel() {
    $(this).dialog('close');
}

function createLeafCertResponse(result) {
    // BUG click issue
    $('#generateLeafReset').click();
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
    let type = input.find('.SANType');
    let value = input.find('.SANValue');
    let spanId = 'SAN' + list.children().length;
    let newSpan = $(`<div id=${spanId}></div>`);
    let newButton = $(`<input type='button' value='✘' onClick="removeSAN('${spanId}')"></input>`);
    let newEntry = $(`<input type='text' name='SANArray' value='${type.val()}: ${value.val()}' class='SANList' readonly></input>`);
    newSpan.append(newButton);
    newSpan.append(newEntry);
    list.append(newSpan);
    type.val('DNS');
    value.val('');
}

function removeSAN(spanId) {
    $(`#${spanId}`).remove();
}

// Update the page with updates sent via the WebSocket
function processUpdates(changePacket) {
    console.log('Changes: ' + changePacket);
    changeJSON = JSON.parse(changePacket);
    let lists = ['#rootList', '#intermediateList', '#leafList', '#keyList'];

    changeJSON.deleted.forEach((change) => {
        console.log(change);
        $(`#${change.type == 4? 'k' : 'c'}${change.id}`).remove();
    });

    lists.forEach((header) => {
        if ($(`${header} li`).length == 0) {
            $(header).append('<li class="empty">None</li>');
        }
    });

    changeJSON.added.forEach(async (change) => {
        let certs = [];
        let result = await getName(change.type, change.id);
        let header = $(`${lists[change.type - 1]} li`);
        let entry = (change.type == 4? buildKeyEntry(result) : buildCertEntry(result));

        if (header.length > 0 && header.first().attr('class') == 'empty') {
            header.first().remove();
        }

        $(`#${typeLookup[change.type]}List li`).each(function() {
            let span = $(this).find('span.certName');
            certs.push({ parent: $(this), span: span.text() });
        });
        if (certs.length == 0) {
            $(`#${typeLookup[change.type]}List`).append(entry);
        }
        else if (result.name.localeCompare(certs[certs.length - 1].span) == 1) {
            certs[certs.length - 1].parent.after(entry);
        }
        else {
            for (let i = 0; i < certs.length; i++) {
                if (result.name.localeCompare(certs[i].span) == -1) {
                    certs[i].parent.before(entry);
                    break;
                }
            }
        }
    });

    changeJSON.updated.forEach(async (change) => {
        let idName = change.type == 4? '#k' : '#c';
        let name = $(`${idName}${change.id} .certValue`);
        if (change.type == 4) {
            let keyDetails = await getKeyDetails({ id: change.id });
            if (keyDetails.name != name.text()) {
                // remove and reinsert
                let newChange = { deleted: [ { type: change.type, id: change.id}], added: [ { type: change.type, id: change.id }], updated: [] };
                processUpdates(JSON.stringify(newChange));
            }

            let details = null;
            if ((details =  $(`#id_${change.type}_${change.id} .keyDetails`))) {
                $(`${idName}${change.id} .keyNameValue`).text(keyDetails.name);
                $(`${idName}${change.id} .keyPairValue`).text(keyDetails.certPair);
            }
        }
        else {
            let info = $(`${idName}${change.id} .certInfo`);
            if (info.length > 0) {
                try {
                    let result = await getCertDetails({ id: change.id });
                    $(`${idName}${change.id} .certTags`).text(`${result.tags.join(';')}`);
                    $(`${idName}${change.id} .certPrivateKey`).text(result.keyPresent == 'yes'? ' with private key' : '');
                    $(`${idName}${change.id} .certInfoSignerValue`).text(result.signer);
                    $(`${idName}${change.id} .certInfoKeyValue`).text(result.keyPresent);
                    $(`${idName}${change.id} .certTagsValue`).text(result.tags.join(';'));
                    if (result.keyPresent == 'no') $(`${idName}${change.id} .certOptionalButtons`).hide();
                    else $(`${idName}${change.id} .certOptionalButtons`).show();
                }
                catch({ error, message }) {
                    showError(error, message);
                }
            }
        }
    });
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

    // Populate the page
    let files;
    [ 
        ['root', buildCertList], 
        ['intermediate', buildCertList], 
        ['leaf', buildCertList], 
        ['key', buildKeyList] 
    ].forEach(async (entry) => { 
        files = await getDir(entry[0]);
        entry[1]($(`#${entry[0]}List`), files.files);
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

    let connectWebSocket = () => {
        let wsURL = (window.location.protocol == 'https:'? 'wss://' : 'ws://') + 
        window.location.hostname + 
        ':' + window.location.port;
        const ws = new WebSocket(wsURL);
        ws.onopen = wsonopen;
        ws.onclose = wsonclose;
        ws.onerror = wsonerror;
        ws.onmessage =  wsonmessage;
    }
    let wsonopen = (e) => {
        console.log('WebSocket is open');
    }
    let wsonclose = (e) => {
        console.log('WebSocket is closed - reopening');
        connectWebSocket();
    }
    let wsonerror = (e) => {
        console.log('WebSocket error: ' + e.message);
    }
    let wsonmessage = (e) => {
        //- console.log('Received: ' + e.data);
        if (e.data != 'Connected') {
        processUpdates(e.data);
        }
    }
    connectWebSocket();
});
