<?php

namespace idunion\sdjwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;
use UnexpectedValueException;

final class StatusList
{
    private const STATUSLIST_TYP = "statuslist+jwt";
    private const STATUSLIST_CLAIM = "status_list";
    private const STATUSLIST_BITS = "bits";
    private const STATUSLIST_LIST = "lst";

    private const STATUSLIST_REF_CLAIM = "status";
    private const STATUSLIST_REF_INDEX = "idx";
    private const STATUSLIST_REF_URI = "uri";

    protected $list = null;
    protected $divisor = 0;
    protected $bits = 0;

    public static function has_status($jwt)
    {
        return isset($jwt->{self::STATUSLIST_REF_CLAIM});
    }

    public static function get_uri($jwt)
    {
        return $jwt->{self::STATUSLIST_REF_CLAIM}->{self::STATUSLIST_REF_URI};
    }

    public static function get_idx($jwt)
    {
        return $jwt->{self::STATUSLIST_REF_CLAIM}->{self::STATUSLIST_REF_INDEX};
    }

    # we expect url and jwk (issuer public key) as input
    public function __construct(string $url, Key $issuer_jwk)
    {
        # fetch status list
        $statuslist_raw = file_get_contents($url);
        if (empty($statuslist_raw)) {
            throw new UnexpectedValueException('could not fetch status list');
        }
        # decode jwt with issuer key (simpification for demo purposes)
        $header = new stdClass;
        $statuslist_token = JWT::decode($statuslist_raw, $issuer_jwk, $header);
        # check for correct header typ
        if($header->typ != self::STATUSLIST_TYP) {
            throw new UnexpectedValueException('status list has wrong typ');
        }
        $list_raw = $statuslist_token->{self::STATUSLIST_CLAIM}->{self::STATUSLIST_LIST};
        $list_decoded = self::base64_decode_urlsafe($list_raw);
        $list = gzdecode($list_decoded);
        $this->list = unpack('C*', $list, 0);
        $bits = $statuslist_token->{self::STATUSLIST_CLAIM}->{self::STATUSLIST_BITS};
        $this->divisor = 8 / $bits;
        $this->bits = $bits;
    }

    private static function base64_decode_urlsafe(string $raw): string | false
    {
        $raw = str_replace("_", "/", $raw);
        $raw = str_replace("-", "+", $raw);
        $padding = strlen($raw) % 4;
        if ($padding > 0) {
            $raw .= str_repeat("=", $padding);
        }
        return base64_decode($raw);
    }

    public function get(int $pos): int {
        if(is_null($this->list)) {
            throw new UnexpectedValueException('status list not set');
        }
        $rest = $pos % $this->divisor;
        $floored = floor($pos / $this->divisor);
        $shift = $rest * $this->bits;
        $status =  ($this->list[$floored+1] & (((1 << $this->bits) - 1) << $shift)) >> $shift;
        return $status;
    }
}
