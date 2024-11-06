chrome.devtools.network.onRequestFinished.addListener(
    function(request) {
        console.log(request.response, 111);
    }
);