<?php

namespace idunion\sdjwt;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

JWT::$timestamp = 1685254200;

final class SDJWTTest extends TestCase
{
    public const FIXTURES_DIR = __DIR__ . '/data/';
    /**
     * @test
     */
    public function testSplit()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation.txt");
        // test key resolution function
        $out = SDJWT::split($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        });
        $this->assertisObject($out);
    }
    /**
    * @test
    */
    public function testDecodeInvalidAudience()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation.txt");
        $this->expectException(UnexpectedValueException::class);
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "invalid", "XZOUco1u_gEPknxS78sWWg", true);
    }

    public function testDecodeValidAudience()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg");
        $this->assertisObject($out);
    }

    public function testSecondPresentation()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation_2.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg");
        $this->assertisObject($out);
    }

    public function testDecodeValidOutput()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg");
        $verified = file_get_contents(SDJWTTest::FIXTURES_DIR . "verified_contents.json");
        $verified = json_decode($verified, false, 512, JSON_BIGINT_AS_STRING);
        $this->assertEquals($verified, $out);
    }

    public function testDecodeValidOutputComplex()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation_complex.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg", false);
        $verified = file_get_contents(SDJWTTest::FIXTURES_DIR . "verified_complex.json");
        $verified = json_decode($verified, false, 512, JSON_BIGINT_AS_STRING);
        $this->assertEquals($verified, $out);
    }

    public function testDecodeValidOutputRecursive()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation_recursive.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg", false);
        $verified = file_get_contents(SDJWTTest::FIXTURES_DIR . "verified_recursive.json");
        $verified = json_decode($verified, false, 512, JSON_BIGINT_AS_STRING);
        $this->assertEquals($verified, $out);
    }

    public function testDecodeValidOutputRecursiveReverseOrder()
    {
        $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "presentation_recursive_order.txt");
        $out = SDJWT::decode($input, function (string $issuer, $kid): string {
            $input = file_get_contents(SDJWTTest::FIXTURES_DIR . "key.json");
            return $input;
        }, "https://example.com/verifier", "XZOUco1u_gEPknxS78sWWg", false);
        $verified = file_get_contents(SDJWTTest::FIXTURES_DIR . "verified_recursive.json");
        $verified = json_decode($verified, false, 512, JSON_BIGINT_AS_STRING);
        $this->assertEquals($verified, $out);
    }
}
