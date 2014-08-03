$(function() {
    // Set up main editor
    $('textarea#main-editor').autosize().focus();

    // Set up keybinds
    Mousetrap.bind(['mod+s'], function(e) {
        $.post(window.location.pathname + '/update', {
            content: $('textarea#main-editor').val(),
            cursor: $('textarea#main-editor').textrange('get', 'position')
        },
        function(data) {
        });

        // Disable default browser behavior
        return false;
    });
});