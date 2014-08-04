$(function() {
    
    function update() {
        $.post(window.location.pathname + '/update', {
            content: $('textarea#main-editor').val(),
            cursor: $('textarea#main-editor').textrange('get', 'position')
        },
        function(data) {
        });  
    }
    // Set up main editor
    $('textarea#main-editor').autosize().focus();

    // Set up keybinds
    Mousetrap.bind(['mod+s'], function(e) {
        update();
        return false;
    });

    Mousetrap.bind(['tab'], function(e) {
        var start = $('textarea#main-editor').textrange('get', 'position');
        var end = $('textarea#main-editor').textrange('get', 'end');
        $('textarea#main-editor').val($('textarea#main-editor').val().substring(0, start)
                + "\t"
                + $('textarea#main-editor').val().substring(end));
        $('textarea#main-editor').textrange('setcursor', start + 1)
        return false;
    });

    // Set up autosave
    var time = new Date();
    var timer = setTimeout(update, 500);
    $('textarea#main-editor').on("change keyup paste click", function(){
        if (new Date() - time < 500) {
            clearTimeout(timer);
        }
        timer = setTimeout(update, 500);
        time = new Date();
    });

    /*$(document).on('click', function(event) {
        if (!$(event.target).closest('textarea#main-editor').length) {
            alert('outside!');  
        }
    });*/
});