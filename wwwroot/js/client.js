// Turn off ESLint (Windows): Tools - Options - Text Editor - Javascript - Linting
$(function () {
    getEvents(1)

    function getEvents(page) {
        $.getJSON({
            url: "../api/event/page" + page,
            success: function (response, textStatus, jqXhr) {
                console.log(response);
            },
            error: function (jqXHR, textStatus, errorThrown) {
                // log the error to the console
                console.log("The following error occured: " + textStatus, errorThrown);
            }
        });
    }
});
