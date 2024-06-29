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
 * Called to remove a tag from the certificates tags.
 * 
 * @param {number} tagIndex index of the tag to remove
 */
function tagDelete(tagIndex) {
    $(`#tag${tagIndex}`).remove();
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
 * Close the tags form
 */
function resetTagForm() {
    $('#tagsEdit').dialog('close');
}

/**
 * Searches for certificates that contain a string in the tags that matches the input filter. Hides any lines that don't.
 */
function searchTags() {
    let filter = $('#tagChooserValue').val();
    let keyIds = [];
    let r = new RegExp(filter, $('#tagCaseLabelCBox').is(':checked') ? 'i' : '');
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
 * Called when the certificate's tags are successfully updated.
 * 
 * @param {{ message: string }} result the result message
 */
function updateTagsDisplay(result) {
    $('tagsCancelButton').trigger('click');
    showMessage(result);
    $('#tagsEdit').dialog('close');
}

function initTags() {
    $('#tagsEditForm').ajaxForm({
        dataType: 'json',
        success: updateTagsDisplay,
        error: (xhr, _msg, err) => {
            showMessage(xhr.responseJSON);
        }
    });

    $('#tagsEdit').dialog({
        autoOpen: false,
        modal: true,
        width: 450,
    });
}