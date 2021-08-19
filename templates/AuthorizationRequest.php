<div class="myapp-element" style="width: 100%;">
    <div class="center">
        <h1>Wallet App Login</h1>
        <p>Scan the following QR code with the wallet app on your phone.</p>
        <a href="<?php p($_['arPost']); ?>"><img src="<?php p($_['qr']); ?>" alt="QR Code" /></a>
        <br>
        <br>
        <h2>OR</h2>
        <br>
        <a class="button" href="<?php print_unescaped($_['ar']) ?>">Authenticate with Wallet App on this device</a>
    </div>
</div>

<input type="hidden" id="pollingUri" value="<?php p($_['pollingUri']); ?>">
<input type="hidden" id="callbackUri" value="<?php p($_['callbackUri']); ?>">

<?php

script('oidc_login', 'bundle');
style('oidc_login', 'AuthorizationRequest'); 
