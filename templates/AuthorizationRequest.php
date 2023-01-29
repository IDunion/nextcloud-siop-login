<div class="center">
    <div class="card">
        <h1><b>Wallet App Login</b></h1>
        <br>
        <br>
        <a class="button custom-button" href="<?php print_unescaped($_['ar']) ?>">Authenticate with your wallet app on this device</a>
        <br>
        <br>
        <h2>OR</h2>
        <p class="description">Scan the following QR code with the wallet app on your phone:</p>
        <a href="<?php p($_['arPost']); ?>"><img class="qrcode" src="<?php p($_['qr']); ?>" alt="QR Code" /></a>
    </div>
</div>

<input type="hidden" id="pollingUri" value="<?php p($_['pollingUri']); ?>">
<input type="hidden" id="callbackUri" value="<?php p($_['callbackUri']); ?>">

<?php

script('ssi_login', 'bundle');
style('ssi_login', 'AuthorizationRequest'); 
