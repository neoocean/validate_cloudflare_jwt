<?php

    use \Firebase\JWT\JWT;
    use \CoderCat\JWKToPEM\JWKConverter;

    include('config.php');

    $current_link = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    if(isCloudflareAccessValidateNeeded() === true) {
        session_expire();
        if(session_validate() === false) { 
            $decoded_jwt = decode();
            if(cursory_validate($decoded_jwt) === false) { 
                die('Failed to Cursory validate.');
            }
            else { 
                session_new();
            }
        }
    }
    // 인증완료. 다음으로 진행.

    function debug($message) {
        global $debug;
        if($debug === true) {
            echo($message . '<br />');            
        }
        return;
    }

    // 이 주소를 밸리데이팅 할지 결정한다.
    function isCloudflareAccessValidateNeeded() {
        debug(__FUNCTION__);        

        $current_link = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $jwt = getCloudflareAccessJWT();
        if((isCloudflareAccessUrl($current_link) === true) && ($jwt !== false)) {
            return(true);
        } 
        return(false);
    }

    // 요청받은 URL이 CFA주소 중 하나인지 확인한다.
    function isCloudflareAccessUrl($current_link) { 
        debug(__FUNCTION__);
        global $validate_url;
        foreach($validate_url as $v) {
            if(strpos($current_link, $v) !== false) {
                return(true);
            }
        }
        return(false);
    }

    // 형식적 확인. 지금은 aud가 일치하는지만 확인하고 있음.
    function cursory_validate($r) {
        debug(__FUNCTION__);
        global $aud;
        foreach($aud as $a) {
            foreach($r->aud as $b) {
                if($a == $b) {
                    return(true);
                }
            }
        }
        return(false);
    }

    function getTimestamp() {
        debug(__FUNCTION__);
        $date = new DateTime();
        return($date->getTimestamp());
    }

    // CFA 쿠키와 일치하는 세션이 있는지 확인한다.
    function session_validate() { 
        debug(__FUNCTION__);
        global $absolute_path;
        global $session_duration;

        $sessions = session_read();
        if(empty($sessions)) { 
            return(false);
        }

        $jwt = getCloudflareAccessJWT();
        $session_key = base64_encode(hash('sha512', $jwt, true));
        
        if($sessions[$session_key] <= (getTimestamp() + $session_duration)) { 
            return(true);
        }
        else {
            return(false);
        }
    }

    // 세션파일을 읽어 세션배열을 돌려준다.
    function session_read() { 
        debug(__FUNCTION__);
        global $absolute_path;        
        global $session_filename;

        if(file_exists($absolute_path . $session_filename) === false) {
            if($file = fopen($absolute_path . $session_filename,'w') === false) {
                die('Failed to create Session File.');
            }
            if(fclose($file) === false) {
                die('Failed to close Session file.');
            }
        }

        $sessions = file_get_contents($absolute_path . $session_filename, true);
        if($sessions === false) {
            die('Failed to open Session file.');
        }
        if(empty($sessions) === true) {
            $sessions = array();
        } else {
            $sessions = json_decode($sessions);
            $sessions = get_object_vars($sessions);            
        }
        return($sessions);
    }

    // 세션배열을 받아 세션파일에 쓴다.
    function session_write($sessions) { 
        debug(__FUNCTION__);
        global $absolute_path;
        global $session_filename;

        if(file_put_contents($absolute_path . $session_filename, json_encode($sessions)) === false) {
            die('Failed to write Session file.');
        } else {
            return;
        }
    }

    // 만료된 세션을 정리한다.
    function session_expire() { 
        debug(__FUNCTION__);
        global $session_duration;

        $sessions = session_read();
        if(empty($sessions) === true) {
            return;
        }
        foreach($sessions as $key => $value) {
            if($value + $session_duration <= getTimestamp()) {
                unset($sessions[$key]);
            }
        }
        session_write($sessions);
        return;
    }

    // CFA 쿠키를 열어 토큰 전체를 해싱해 기록한다. (토큰을 안 열어보려고)
    function session_new() {
        debug(__FUNCTION__);

        $jwt = getCloudflareAccessJWT();
        $sessions = session_read();

        $session_key = base64_encode(hash('sha512', $jwt, true));
        $sessions[$session_key] = getTimestamp();

        if(session_write($sessions) === false) {
            die('Failed to write a session.');
        }
    }

    // CFA 쿠키를 읽어 JWT를 돌려준다.
    function getCloudflareAccessJWT() {
        debug(__FUNCTION__);
        $jwt = $_COOKIE['CF_Authorization'];
        if(empty($jwt) === true) { 
            return(false);
        }
        return($jwt);
    }

    // JWT를 디코딩하고 밸리데이팅한다.
    function decode() {
        debug(__FUNCTION__);
        global $absolute_path;

        include($absolute_path . 'src/JWT.php');
        include($absolute_path . 'src/phpseclib1.0.18/Crypt/RSA.php');
        include($absolute_path . 'src/JWKConverter.php');
        include($absolute_path . 'src/Util/Base64UrlDecoder.php');
        include($absolute_path . 'src/Exception/Base64DecodeException.php');
        include($absolute_path . 'src/Exception/JWKConverterException.php');
        
        global $cert_url;

        $json = file_get_contents($cert_url);
        if($json === false) {
            die('Failed to load certs.');
        }
        $obj = json_decode($json);
        
        // 가져온 PK를 JWK to PEM 하기.
        $publicKey = array();
        $jwkConverter = new JWKConverter();
        foreach($obj->keys as &$v) {
            $convertedJwk = $jwkConverter->toPEM((array)$v);
            $publicKey[$v->kid] = $convertedJwk;
        }

        $jwt = getCloudflareAccessJWT();

        return(JWT::decode($jwt, $publicKey, array('RS256')));
    }

