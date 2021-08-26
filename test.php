<?php
// RUN: php test.php

include 'lib/LibIndyWrapper/LibIndy.php';

$libIndy = new LibIndy();
$future = $libIndy->createSchema("CsiDLAiFkQb9N4NDJKUagd", 'test', "0.1", '["name"]');
var_dump($future->get());

//$libIndy->setDefaultLogger("trace");
putenv("HOME=/tmp"); // workaround for lib indy to load the genesis file
$configName = "idunion_test_ledger";
$config = '{"genesis_txn":"'.__DIR__.'/lib/LibIndyWrapper/genesis_txn.txt"}';
try {
    $libIndy->createPoolLedgerConfig($configName, $config)->get();
} catch (LibIndyException $e) {
    $libIndy->deletePoolLedgerConfig($configName)->get();
    $libIndy->createPoolLedgerConfig($configName, $config)->get();
}
var_dump("Pool ledger config created");
