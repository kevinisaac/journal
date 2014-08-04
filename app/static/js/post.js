$(function() {
    
    var cached_text = "";
    function update() {
        if (cached_text !=  $('textarea#main-editor').val()) {
            cached_text = $('textarea#main-editor').val()
            $.post(window.location.pathname + '/update', {
                content: cached_text,
                cursor: $('textarea#main-editor').textrange('get', 'position')
            },
            function(data) {
            });
        }
        else {
            $.post(window.location.pathname + '/update', {
                cursor: $('textarea#main-editor').textrange('get', 'position')
            },
            function(data) {
            });
        }
    }

    // Convert timestamps
    $('.timestamp').each(function(index) {
        $(this).text(moment($(this).text()).format('M/D').toLocaleString());
    });

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