<div class="background-color" style="width: 100%;">
    <div class="center background-color">
        <h1>Wallet App Login</h1>
        <br>
        <br>
        <a class="button" href="<?php print_unescaped($_['ar']) ?>">Authenticate with Wallet App on this device</a>
        <br>
        <br>
        <br>
        <h2>OR</h2>
        <p>Scan the following QR code with the wallet app on your phone:</p>
        <a href="<?php p($_['arPost']); ?>"><img class="qrcode" src="<?php p($_['qr']); ?>" alt="QR Code" /></a>
    </div>
</div>

<input type="hidden" id="pollingUri" value="<?php p($_['pollingUri']); ?>">
<input type="hidden" id="callbackUri" value="<?php p($_['callbackUri']); ?>">

<?php

script('ssi_login', 'bundle');
style('ssi_login', 'AuthorizationRequest'); 
