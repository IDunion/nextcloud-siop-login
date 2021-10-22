<?php

function getEncoding($value) {
    if(empty($value)) {
        $value = '';
    } elseif(is_integer($value)) {
        $value = strval($value);
    }

    $hex = hash('sha256', utf8_encode($value), false);
    $bigInt = gmp_init($hex, 16);
    return gmp_strval($bigInt);
}


if (getEncoding('Wonderland') == '16790849312374794736813377567253851373607970473377701477269194019557654562035') {
    echo "Success\n";
}
if (getEncoding('alice@example.com') == '115589951590854546960691112648251660507865356487762333837470597583915671017846') {
    echo "Success\n";
}
if (getEncoding('Alice') == '27034640024117331033063128044004318218486816931520886405535659934417438781507') {
    echo "Success\n";
}