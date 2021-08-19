if(OCA.Theming) {
    console.log("change color");
    $('.myapp-element').css({backgroundColor:OCA.Theming.color});
}

$(document).ready(function() {
    var pollingUri = $("#pollingUri").val();
    var callbackUri = $("#callbackUri").val();
    doPolling(pollingUri, callbackUri);
});

function doPolling(pollingUri, callbackUri) {
    $.get(pollingUri, function(data, status) {
        console.log(data["finished"]);
        if (!data["finished"]) {
            setTimeout(doPolling, 1000, pollingUri, callbackUri);
        } else {
            window.location.replace(callbackUri + "?from_file=true");
        }
    })
}