<?php

    // 스크립트가 실행될 절대경로
    $absolute_path = '/home/bitnami/cloudflare/validate_cloudflare_jwt/';

    // JWT를 확인해야 하는 URL 목록: validate_url[]
    $validate_url[0] = 'neoocean.net/cloudflare_access_protected/';
    $validate_url[1] = 'cloudflare_access_protected.neoocean.net/';

    // 액세스의 AUD 목록: aud[]
    $aud[0] = '0000000000000000000000000000000000000000000000000000000000000000';
    $aud[1] = '0000000000000000000000000000000000000000000000000000000000000000';

    // 액세스 인증서 주소
    $cert_url = 'https://neoocean.cloudflareaccess.com/cdn-cgi/access/certs';

    // 세션 길이 (초)
    $session_duration = 3600;

    $session_filename = 'sessions.json';
    $debug = false;
