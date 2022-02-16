if(OCA.Theming) {
    console.log("change color");
    $('.background-color').css({backgroundColor:OCA.Theming.color});
}

// This variable is used to stop polling as soon
// as the browser is redirected.
var redirected = false;

$(document).ready(function() {
    var pollingUri = $("#pollingUri").val();
    var callbackUri = $("#callbackUri").val();
    doPolling(pollingUri, callbackUri);
});

function doPolling(pollingUri, callbackUri) {
    // Don't poll after the browser was redirected
    if (!redirected) {
        $.get(pollingUri, function(data) {console.log(data["finished"]);
            // Check if the authentication process finished and
            // if the browser was already redirected
            if (data["finished"] && !redirected) {
                redirected = true;
                window.location.replace(callbackUri);
            }
        });
    }
    setTimeout(doPolling, 1000, pollingUri, callbackUri);
}