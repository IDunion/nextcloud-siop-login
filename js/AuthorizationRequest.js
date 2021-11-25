if(OCA.Theming) {
    console.log("change color");
    $('.background-color').css({backgroundColor:OCA.Theming.color});
}

$(document).ready(function() {
    var pollingUri = $("#pollingUri").val();
    var callbackUri = $("#callbackUri").val();
    doPolling(pollingUri, callbackUri);
});

function doPolling(pollingUri, callbackUri) {
    $.get(pollingUri, function(data) {console.log(data["finished"]);
        if (data["finished"]) {
            window.location.replace(callbackUri);
        }
    });
    setTimeout(doPolling, 1000, pollingUri, callbackUri);
}