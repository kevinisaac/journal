$(function() {
    // Set up main editor
    $('textarea#main-editor').autosize().focus();

    // Set up keybinds
    Mousetrap.bind(['mod+s'], function(e) {
        $.post(window.location.pathname + '/update', {
            content: $('textarea#main-editor').val()
        },
        function(data) {
        });
        console.log('command shift k'); 

        // Disable default browser behavior
        return false;
    });
});