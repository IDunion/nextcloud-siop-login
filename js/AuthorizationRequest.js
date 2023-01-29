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
        $.get(pollingUri, function(data) {
            // Check if the authentication process finished and
            // if the browser was already redirected
            if (data["finished"] && !redirected) {
                redirected = true;
                window.location.replace(callbackUri);
            }
        });
    }
    setTimeout(doPolling, 2000, pollingUri, callbackUri);
}