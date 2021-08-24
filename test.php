<?php

include 'lib/LibIndyWrapper/LibIndy.php';

$libIndy = new LibIndy();
$future = $libIndy->createSchema("CsiDLAiFkQb9N4NDJKUagd", 'test', "0.1", '["name"]');
var_dump($future->get());

$future = $libIndy->verifierVerifyProof("{}","{}","{}","{}","{}","{}");
var_dump($future->get());


/*
$ffi = FFI::cdef(
    "
    typedef enum
    {
        Success = 0,

        // Common errors

        // Caller passed invalid value as param 1 (null, invalid json and etc..)
        CommonInvalidParam1 = 100,

        // Caller passed invalid value as param 2 (null, invalid json and etc..)
        CommonInvalidParam2 = 101,

        // Caller passed invalid value as param 3 (null, invalid json and etc..)
        CommonInvalidParam3 = 102,

        // Caller passed invalid value as param 4 (null, invalid json and etc..)
        CommonInvalidParam4 = 103,

        // Caller passed invalid value as param 5 (null, invalid json and etc..)
        CommonInvalidParam5 = 104,

        // Caller passed invalid value as param 6 (null, invalid json and etc..)
        CommonInvalidParam6 = 105,

        // Caller passed invalid value as param 7 (null, invalid json and etc..)
        CommonInvalidParam7 = 106,

        // Caller passed invalid value as param 8 (null, invalid json and etc..)
        CommonInvalidParam8 = 107,

        // Caller passed invalid value as param 9 (null, invalid json and etc..)
        CommonInvalidParam9 = 108,

        // Caller passed invalid value as param 10 (null, invalid json and etc..)
        CommonInvalidParam10 = 109,

        // Caller passed invalid value as param 11 (null, invalid json and etc..)
        CommonInvalidParam11 = 110,

        // Caller passed invalid value as param 12 (null, invalid json and etc..)
        CommonInvalidParam12 = 111,

        // Invalid library state was detected in runtime. It signals library bug
        CommonInvalidState = 112,

        // Object (json, config, key, credential and etc...) passed by library caller has invalid structure
        CommonInvalidStructure = 113,

        // IO Error
        CommonIOError = 114,

        // Wallet errors
        // Caller passed invalid wallet handle
        WalletInvalidHandle = 200,

        // Unknown type of wallet was passed on create_wallet
        WalletUnknownTypeError = 201,

        // Attempt to register already existing wallet type
        WalletTypeAlreadyRegisteredError = 202,

        // Attempt to create wallet with name used for another exists wallet
        WalletAlreadyExistsError = 203,

        // Requested entity id isn't present in wallet
        WalletNotFoundError = 204,

        // Trying to use wallet with pool that has different name
        WalletIncompatiblePoolError = 205,

        // Trying to open wallet that was opened already
        WalletAlreadyOpenedError = 206,

        // Attempt to open encrypted wallet with invalid credentials
        WalletAccessFailed = 207,

        // Input provided to wallet operations is considered not valid
        WalletInputError = 208,

        // Decoding of wallet data during input/output failed
        WalletDecodingError = 209,

        // Storage error occurred during wallet operation
        WalletStorageError = 210,

        // Error during encryption-related operations
        WalletEncryptionError = 211,

        // Requested wallet item not found
        WalletItemNotFound = 212,

        // Returned if wallet's add_record operation is used with record name that already exists
        WalletItemAlreadyExists = 213,

        // Returned if provided wallet query is invalid
        WalletQueryError = 214,

        // Ledger errors
        // Trying to open pool ledger that wasn't created before
        PoolLedgerNotCreatedError = 300,

        // Caller passed invalid pool ledger handle
        PoolLedgerInvalidPoolHandle = 301,

        // Pool ledger terminated
        PoolLedgerTerminated = 302,

        // No concensus during ledger operation
        LedgerNoConsensusError = 303,

        // Attempt to parse invalid transaction response
        LedgerInvalidTransaction = 304,

        // Attempt to send transaction without the necessary privileges
        LedgerSecurityError = 305,

        // Attempt to create pool ledger config with name used for another existing pool
        PoolLedgerConfigAlreadyExistsError = 306,

        // Timeout for action
        PoolLedgerTimeout = 307,

        // Attempt to open Pool for witch Genesis Transactions are not compatible with set Protocol version.
        // Call pool.indy_set_protocol_version to set correct Protocol version.
        PoolIncompatibleProtocolVersion = 308,

        // Item not found on ledger.
        LedgerNotFound = 309,

        // Revocation registry is full and creation of new registry is necessary
        AnoncredsRevocationRegistryFullError = 400,

        AnoncredsInvalidUserRevocId = 401,

        // Attempt to generate master secret with dupplicated name
        AnoncredsMasterSecretDuplicateNameError = 404,

        AnoncredsProofRejected = 405,

        AnoncredsCredentialRevoked = 406,

        // Attempt to create credential definition with duplicated did schema pair
        AnoncredsCredDefAlreadyExistsError = 407,

        // Crypto errors
        // Unknown format of DID entity keys
        UnknownCryptoTypeError = 500,

        // Attempt to create duplicate did
        DidAlreadyExistsError = 600,

        // Unknown payment method was given
        PaymentUnknownMethodError = 700,

        //No method were scraped from inputs/outputs or more than one were scraped
        PaymentIncompatibleMethodsError = 701,

        // Insufficient funds on inputs
        PaymentInsufficientFundsError = 702,

        // No such source on a ledger
        PaymentSourceDoesNotExistError = 703,

        // Operation is not supported for payment method
        PaymentOperationNotSupportedError = 704,

        // Extra funds on inputs
        PaymentExtraFundsError = 705
    } indy_error_t;

    typedef uint8_t       indy_u8_t;
    typedef uint32_t      indy_u32_t;
    typedef int32_t       indy_i32_t;
    typedef int32_t       indy_handle_t;
    typedef bool          indy_bool_t;
    typedef long long     indy_i64_t;
    typedef unsigned long long     indy_u64_t;
    extern indy_error_t indy_issuer_create_schema(indy_handle_t command_handle,
            const char *  issuer_did,
            const char *  name,
            const char *  version,
            const char *  attr_names,

            void           (*cb)(indy_handle_t command_handle_,
                                indy_error_t  err,
                                const char*   id,
                                const char*   schema_json)
            );
    extern indy_error_t indy_create_wallet(indy_handle_t  command_handle,
            const char*    config,
            const char*    credentials,
            void           (*fn)(indy_handle_t command_handle_, indy_error_t err)
           );",
    "libindy.so"
    );

$future = new Future(1);

// Tutorial: https://phpconference.com/blog/php-ffi-and-what-it-can-do-for-you/
$cb = function (int $command_handle, int $err, string $id, string $schema_json) {
    var_dump("Success\n");
    //var_dump($schema_json);
    $queue = msg_get_queue($command_handle);
    msg_send($queue, 1, $schema_json);
};

$cb2 = function (int $command_handle, int $err) {
    var_dump("Success\n");
};

$handle = $ffi->new("indy_handle_t");

$handle->cdata = 1;

$did = $ffi->new("char[22]");
FFI::memcpy($did, "CsiDLAiFkQb9N4NDJKUagd", 22);
$name = $ffi->new("char[4]");
FFI::memcpy($name, "test", 4);
$version = "0.1";
$attr = $ffi->new("char[8]");
FFI::memcpy($attr, "[\"name\"]", 8);

echo "Call Indy SDK\n";
//echo $ffi->indy_create_wallet(2, '{"id": "my_wallet"}', '{"key":"8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY", "key_derivation_method":"RAW"}', $cb2) . "\n";
echo $ffi->indy_issuer_create_schema($future->getQueueKey(), "CsiDLAiFkQb9N4NDJKUagd", 'test', $version, '["name"]', $cb) . "\n";
var_dump($future->get());
echo "End\n";
