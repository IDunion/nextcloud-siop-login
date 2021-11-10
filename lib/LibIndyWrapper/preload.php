<?php
\FFI::load(__DIR__ . "/indy.h");
opcache_compile_file(__DIR__ . "/LibIndy.php");
?>