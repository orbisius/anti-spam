<?php
/**
 * All in one anti-spam solution.
 * Just load it and block all spam assholes.
 * require_once __DIR__ . '/zzz_anti_spam.php';
 *
 * git clone https://orbisius@bitbucket.org/orbisius-products/anti-spam.git
 * Put this in the config file
 * require_once __DIR__ . '/anti-spam/zzz_anti_spam.php';
 *
 * @todo check for these
 * https://github.com/xsuperbug/payloads/blob/master/3.txt
 *
 * check if it's running in qs context or if it already exists???
 *
 * return obj that explains how many points each thing has gotten
 * e.g. matched URLs 5 x 2 =>
 *
 * distinguish between spam & attack
 *
 * Save stats in user's home dir
 */

// Save stats for a year
defined('ORB_ANTI_SPAM_BASE_DIR') || define('ORB_ANTI_SPAM_BASE_DIR', __DIR__);

if (php_sapi_name() == 'cli') {
	global $_SERVER;
	global $_REQUEST;
	$_SERVER['REQUEST_URI'] = empty($argv[1]) ? '' : $argv[1];

	if (!empty($argv[2]) && preg_match('#\.(txt|log)#si', $argv[2])) {
		$_REQUEST = [];
		$_REQUEST['data'] = file_get_contents($argv[2], LOCK_SH);
		$_SERVER['REMOTE_ADDR'] = '';
	}
}

$obj = new orb_anti_spam();
$dev_mode = $obj->is_dev_env();

if ($obj->is_live_env() && $obj->is_ip_ok()) {
    return;
}

$score_rec = [
	'data' => [],
];

$req_score = $obj->calc_request_score();
$body_score = $obj->calc_spam_score($_REQUEST);;

$score_rec['data']['req_score'] = $req_score;
$score_rec['data']['body_score'] = $body_score;
$score_rec['data']['total_score'] = $req_score + $body_score;

echo json_encode($score_rec, JSON_PRETTY_PRINT);
exit;

// simple anti-spam stop
if ($req_score >= 5 || !empty($_POST) || $dev_mode) {
    $ip = $obj->get_ip();
    $ip_hash = $obj->get_ip_hash();

    // We'd like to save this info in wp-content but if it doesn't exist we'll save it in logs/
    $base_dirs = [
        dirname(ORB_ANTI_SPAM_BASE_DIR) . '/wp-content/', // if this is in own dir
        ORB_ANTI_SPAM_BASE_DIR . '/wp-content/', // same dir as wp
        ORB_ANTI_SPAM_BASE_DIR . '/logs/', // no wp
    ];

    $selected_logs_base_dir = $base_dirs[ count($base_dirs) - 1 ];

    foreach ($base_dirs as $base_dir) {
        if (is_dir($base_dir)) {
            $selected_logs_base_dir = $base_dir;
            break;
        }
    }

    $dir = $selected_logs_base_dir . '/.ht_anti_spam/logs' . date('/Y/');

    $dir .=     substr($ip_hash, 0, 1)
        . '/' . substr($ip_hash, 1, 1)
        . '/' . substr($ip_hash, 2, 1)
        . '/' . substr($ip_hash, 3, 1);

    if (!is_dir($dir)) {
        mkdir($dir, 0755, 1);
    }

    $file = $dir . '/' . $ip . '.txt';

    $score = $obj->calc_spam_score($_REQUEST);

    if ($score >= 5 || file_exists($file)) {
        $rec = [
            "date" => date('r'),
            "spam_score" => $score,
            'req' => $_REQUEST,
            'ip' => $_SERVER['REMOTE_ADDR'],
        ];

        $spam_buff = serialize($rec);
        $spam_buff .= "\n";
//        $spam_buff = base64_encode($spam_buff) . "\n";

        file_put_contents($file, $spam_buff, FILE_APPEND | LOCK_EX);

        if (!$dev_mode) {
            $sleep_time = mt_rand(25, 90);
            sleep($sleep_time);
        }

        $link = 'http://' . $_SERVER['HTTP_HOST'];

        echo "Success. We have most likely received your submission.";
        echo "<br/> Please, <a href='$link'>continue</a>";
        exit;

//        header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
//        die("500 Internal Server Error");
    }
}

class orb_anti_spam {
    private $ip = '';
    private $ip_hash = '';

    /**
     * orb_anti_spam constructor.
     * @return orb_anti_spam
     */
    public function __construct() {
        $ip = empty($_SERVER['REMOTE_ADDR']) ? '' : $_SERVER['REMOTE_ADDR'];
        $ip = strip_tags($ip);
        $ip = trim($ip);
        $this->ip = $ip;

        $ip_hash = sha1($ip);
        $this->ip_hash = $ip_hash;
    }

    function get_ip() {
        return $this->ip;
    }

    function get_ip_hash() {
        return $this->ip_hash;
    }

    /**
     * @return bool
     */
    function is_dev_env() {
        return !$this->is_live_env();
    }

    /**
     * @return bool
     */
    function is_live_env() {
        $live_mode = empty($_SERVER['DEV_ENV']);
        return $live_mode;
    }

    /**
     * @param string $ip
     * @return bool
     */
    function is_ip_ok($ip = '') {
        $known_ips = [
            '127.0.0.1', // localhost
            '87.97.251.227', // tosho
            '77.238.81.152', // home b5
            '94.26.21.60', // cosmos office ip
        ];

        $ip = empty($ip) ? $this->ip : $ip;

        return in_array($ip, $known_ips);
    }

    /**
     * Calculates score of a request by checking if the user should be requesting a given resource.
     * For example config files, passing javascript etc e.g. XSS attacks
     * @param $buff
     */
    function calc_request_score($req = '') {
        $req = empty($buff) ? $_SERVER['REQUEST_URI'] : $req;
        $req = orb_anti_spam_util::decode_entities($req);
        $req = trim($req);
        $score = 0;

        // Some like to get my config file.
        $regex = '#(wp-config|wp-config-sample|/etc/passwd)#si';

        if (preg_match_all($regex, $req, $matches)) {
            $score += count($matches[0]) * 15;
        }

        // script with spaces in it
        $regex = '#(</?\s*s\s*c\s*r\s*i\s*p\s*t\s*|javascript\:|alert\s*\()#si';

        if (preg_match_all($regex, $req, $matches)) {
            $score += count($matches[0]) * 15;
        }

        $regex = '#(debug\.log|\.sql)#si';

        if (preg_match_all($regex, $req, $matches)) {
            $score += count($matches[0]) * 15;
        }

        $regex = '#\b(UNION|UNION[\s\+]+SELECT|/*[\s!\d]*UNION*/)\b#si';

        if (preg_match_all($regex, $req, $matches)) {
            $score += count($matches[0]) * 15;
        }

        return $score;
    }

    /**
     * @param string|array $buff
     * @return int
     */
    function calc_spam_score($buff) {
        $score = 0;

    	if (is_array($buff)) {
    		foreach ($buff as $k => $v) {
			    $score += $this->calc_spam_score($v);
		    }

    		return $score;
	    }

        $buff = is_scalar($buff) ? $buff : var_export($buff, 1);

        // spam phrase
        $url_regex = '#(Hello|hi)[\.\s]*And Bye[\.\s]*#si';

        if (preg_match_all($url_regex, $buff, $matches)) {
            $score += count($matches[0]) * 10;
        }

        // domain
        $url_regex = '#\b([\w\-]+\.[a-z]{2,10}(\.[a-z]{2,10})?)\b#si';

        if (preg_match_all($url_regex, $buff, $matches)) {
            $score += count($matches[0]) * 1;
        }

        // email
        $regex = '#\b([\w\-\.\+]+\@[\w\-]+\.[a-z]{2,10}(\.[a-z]{2,10})?)\b#si';

        if (preg_match_all($regex, $buff, $matches)) {
            $score += count($matches[0]) * 2;
        }

        if (strlen($buff) >= 4 * 1024) {
            $score += 15;
        }

//        $regex = '#\@yandex\.ru#si';
//
//        if (preg_match_all($regex, $buff, $matches)) {
//            $score += count($matches[0]);
//        }

        $regex = '#bit\.ly|bitly\.com#si';

        if (preg_match_all($regex, $buff, $matches)) {
            $score += count($matches[0]) * 2;
        }

        if (preg_match_all( '#\[/?url|\[/?link#si', $buff, $matches )) {
            $score += count($matches[0]) * 5;
        }

        // check for dollar amounts sending 1 million messages is $ 49
        if (preg_match_all( '#(\$\s*\d+[\.\d]*)#si', $buff, $matches ) > 2) {
            $score += count($matches[0]) * 2;
        }

        if (preg_match_all( '#\[b\s*\].*?\[/b\]#si', $buff, $matches )) {
            $score += count($matches[0]) * 5;
        }

        if (preg_match_all( '#https?:/+[\w\-\.\:/\?\%\&\=]+#si', $buff, $matches )) {
            $score += count($matches[0]) * 2;
        }

        // Get from file or ENV
        $phrases = [
        	'Day Loan',
	        'blockchain technology',
	        'make a profit',
        	'Pay Day Loan',
	        'Dear Sir',
	        'Dear Madame',
	        'viagra',
			'penis',
			'cunt',
	        'pussy',
	        'breast',
	        'porn',
			'buy now',
	        'order now',
	        'hurry up',
	        'breast size',
	        'penis size',
	        'Get paid',
	        'earn again',
	        'CLICK HERE',
	        'to unsubscribe',
	        'to unsubscribe click',
	        'more leads today',
	        '#CLICK HERE#s',
	        '#FREE TEST#s',
	        'gift for you',
	        "#PS[:\s]*Don't just take my word for it#si",
	        '#\d+\-?Days?\s+Test\s+Drive#si', // 14-Day Test Drive
	        '#\d+\-?Days?\s+(free\s+)?Trial#si', // 14-Day free trial
        ];

        foreach ($phrases as $phrase) {
        	$first_char = substr($phrase, 0, 1);

        	if (in_array($first_char, [ '#', '/', ] )) {
        		// already quoted regex
		        $regex = $phrase;
	        } else {
		        $phrase_qu = preg_quote( $phrase, '#' );
	            $regex = '#\b(' . $phrase_qu . ')\b#si';
	        }

	        if (preg_match_all( $regex, $buff,$matches )) {
		        $score += count($matches[0]) * 5;
	        }
        }

        return $score;
    }
}

class orb_anti_spam_util {
    /**
     * orb_anti_spam_util::decode_entities();
     * @param $str
     * @see http://php.net/manual/en/function.html-entity-decode.php
     */
    public static function decode_entities($input) {
        $input = is_scalar($input) ? $input : var_export($input, 1);
        $res = html_entity_decode($input, ENT_QUOTES | ENT_XML1, 'UTF-8');
        $res = urldecode($res);

        if (function_exists('mb_convert_encoding')) {
            $output = preg_replace_callback("/(&#[0-9]+;)/si", function($m) {
                return mb_convert_encoding($m[1], "UTF-8", "HTML-ENTITIES");
            }, $res);

            if (!empty($output)) {
                $res = $output;
            }
        }

        return $res;
    }
}
