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
 * Load from Google or another shared location maybe ORB <- google sheets
 * csv
 * keyword phrase | score (empty or > 0)
 * Sync from time to time
 */

// we'll use this library and we don't want it to execute a file on every request but rather load it as a library.
if (php_sapi_name() == 'cli' && preg_match('#bin|projects#si', __FILE__)) {
	$exit_code = 0;
	$score_rec = [
		'msg'    => '',
		'status' => 0,
		'data'   => [],
	];

	try {
		$file      = orb_anti_spam_util::get_field( 'file' );
		$debug     = orb_anti_spam_util::get_field( 'debug' );
		$data      = orb_anti_spam_util::get_field( 'data|buffer|url' );
		$spam_file = orb_anti_spam_util::get_field( 'spam_file' );

		if ( empty( $file ) && empty( $data ) ) {
			throw new Exception( "Missing params. Pass --data or --file" );
		}

		$obj       = new orb_anti_spam( [ 'spam_file' => $spam_file, ] );
		$req_score = $obj->calc_request_score();

		if ( ! empty( $file ) ) {
			if ( ! is_readable( $file ) ) {
				throw new Exception( "File doesn't exist" );
			}

			$score_rec['data']['file']      = $file;
			$score_rec['data']['file_size'] = filesize( $file );
			$data                           = file_get_contents( $file, LOCK_SH );
		}

		if ( ! empty( $data ) ) {
			$body_score = $obj->calc_spam_score( $data );
		} else {
			$body_score = $obj->calc_spam_score( $_REQUEST );
		}

		$score_rec['data']['req_score']   = $req_score;
		$score_rec['data']['body_score']  = $body_score;
		$score_rec['data']['total_score'] = $req_score + $body_score;
		$score_rec['status']              = 1;

		if (!empty($debug)) {
			$score_rec['data']['debug'] = $obj->get_scan_log();
		}
	} catch ( Exception $e ) {
		$score_rec['msg'] = $e->getMessage();
		$exit_code        = 255;
	}

	echo json_encode( $score_rec, JSON_PRETTY_PRINT );
	exit( $exit_code );
}

class orb_anti_spam {
	private $params = [];
	private $scans = [];
	private $remote_spam_definition_urls = [
		[
			// https://stackoverflow.com/questions/33713084/download-link-for-google-spreadsheets-csv-export-with-multiple-sheets
			'label' => 'Orbisius Spam Definitions',
			'url' => 'https://docs.google.com/spreadsheets/d/e/2PACX-1vTrwDRDIreedv7tRlDA4oyEJKec6T2VcwQtA0ybET8snZMKlgJ2V3XmC1cFNOD0nRCXHJ9shEnP_bTT/pub?gid=0&single=true&output=csv',
		],
	];

	public function __construct($params = []) {
		$this->params = $params;
	}

	/**
     * Calculates score of a request by checking if the user should be requesting a given resource.
     * For example config files, passing javascript etc e.g. XSS attacks
     * @param $buff
     */
    function calc_request_score($req = '') {
    	$log_res_obj = new orb_anti_spam_result();

    	if (empty($req)) {
		    if (!empty($_SERVER['REQUEST_URI'])) {
			    $req = $_SERVER['REQUEST_URI'];
		    } elseif (getenv('REQUEST_URI')) {
			    $req = getenv('REQUEST_URI');
		    }
	    }

        $req = orb_anti_spam_util::decode_entities($req);
        $req = trim($req);
        $score = 0;

        // Some like to get my config file.
        $regex = '#(wp-config|wp-config-sample|/etc/passwd)#si';

        if (preg_match_all($regex, $req, $matches)) {
            $local_score = count($matches[0]) * 15;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        // script with spaces in it
        $regex = '#(</?\s*s\s*c\s*r\s*i\s*p\s*t\s*|javascript\:|alert\s*\()#si';

        if (preg_match_all($regex, $req, $matches)) {
	        $local_score = count($matches[0]) * 15;
	        $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        $regex = '#(debug\.log|\.sql)#si';

        if (preg_match_all($regex, $req, $matches)) {
	        $local_score = count($matches[0]) * 15;
	        $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        $regex = '#\b(UNION|UNION[\s\+]+SELECT|/*[\s!\d]*UNION*/)\b#si';

        if (preg_match_all($regex, $req, $matches)) {
	        $local_score = count($matches[0]) * 50;
	        $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        $this->scans['req_calc'] = $log_res_obj;
        return $score;
    }

	/**
	 * @param string $ip
	 */
	function calc_ip_spam_score($ip) {

	}

    /**
     * @param string|array $buff
     * @return int
     */
    function calc_spam_score($buff) {
        $score = 0;
	    $log_res_obj = new orb_anti_spam_result();

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
	        $local_score = count($matches[0]) * 10;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        // domain
        $url_regex = '#([\w\-]+\.[a-z]{2,10}(\.[a-z]{2,10})?)#sim';

        if (preg_match_all($url_regex, $buff, $matches)) {
	        $local_score = count($matches[0]) * 1;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        // email
        $regex = '#\b([\w\-\.\+]+\@[\w\-]+\.[a-z]{2,10}(\.[a-z]{2,10})?)\b#si';

        if (preg_match_all($regex, $buff, $matches)) {
	        $local_score = count($matches[0]) * 2;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        if (strlen($buff) >= 4 * 1024) {
	        $local_score = 15;
            $score += $local_score;
	        $log_res_obj->append('Length is more than 4k', $local_score);
        }

        $regex = '#bit\.ly|bitly\.com#si';

        if (preg_match_all($regex, $buff, $matches)) {
	        $local_score = count($matches[0]) * 2;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        if (preg_match_all( '#\[/?url|\[/?link#si', $buff, $matches )) {
	        $local_score = count($matches[0]) * 5;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

        // check for dollar amounts sending 1 million messages is $ 49 or 49$ or  $ 70,000
	    if (preg_match_all( '#(\$\s*\d+[\,\.\d]*)\s*\$?#si', $buff, $matches ) > 1) {
		    $local_score = count($matches[0]) * 2;
		    $score += $local_score;
		    $log_res_obj->append($matches[0], $local_score);
	    }

	    // 49 USD
	    if (preg_match_all( '#(\d+[\,\.\d]*\s*(\$|USD|US[\s\-]+Dollars?|USD|US[\s\-]+|EURO?S?|CAD|AUD|NZD))#si', $buff, $matches)) {
		    $local_score = count($matches[0]) * 2;
		    $score += $local_score;
		    $log_res_obj->append($matches[0], $local_score);
	    }

	    // 8,5 Millionen
	    if (preg_match_all( '#(\d+[\,\.\d]*\s*(\$|USD|US[\s\-]+Dollars?|EURO?S?|CAD|AUD|NZD)?)[\s\:\-]*(Millionen|millions?)#si', $buff, $matches)) {
		    $local_score = count($matches[0]) * 5;
		    $score += $local_score;
		    $log_res_obj->append($matches[0], $local_score);
	    }

	    // URGENT TRANSFER OF YOUR US$4,500,000.00
	    if (preg_match_all( '#(\$|USD|US[\s\-]*|EURO?S?|CAD|AUD|NZD)(\d+[\,\.\d]*\s*(\$|USD|US[\s\-]+Dollars?|EURO?S?|CAD|AUD|NZD)?)#si', $buff, $matches)) {
		    $local_score = count($matches[0]) * 2;
		    $score += $local_score;
		    $log_res_obj->append($matches[0], $local_score);
	    }

        if (preg_match_all( '#\[b\s*\].*?\[/b\]#si', $buff, $matches )) {
	        $local_score = count($matches[0]) * 5;
	        $score += $local_score;
	        $log_res_obj->append($matches[0], $score);
        }

        if (preg_match_all( '#h\S*t\S*t\S*p\S*s?\S*:\S*/+\S*[\w\-\.\:/\?\%\&\=]+#si', $buff, $matches )) {
	        $local_score = count($matches[0]) * 2;
            $score += $local_score;
	        $log_res_obj->append($matches[0], $local_score);
        }

	    // Let's check if the host is in the current message
	    // spammers have site?u=current-domain.com
	    // we'll check if there's an equal sign in front of the hosts that we've found.
	    $hosts = [];
	    if (!empty($_SERVER['HTTP_HOST'])) {
		    $host = strip_tags($_SERVER['HTTP_HOST']);
		    $host = trim($host);
		    $host = preg_replace('#^www\.#si', '', $host);
		    $hosts[] = $host;
	    }

	    if (!empty($_SERVER['SERVER_NAME'])) {
		    $host = strip_tags($_SERVER['SERVER_NAME']);
		    $host = preg_replace('#^www\.#si', '', $host);
		    $host = trim($host);
		    $hosts[] = $host;
	    }

	    $hosts = array_unique($hosts);

	    foreach ($hosts as $host) {
	    	// site.com/?u=example.com
		    $host_match_regex = '#[\?\&\/][\w\-]*\=.*?' . preg_quote($host) . '#si'; // full or partial match of the domain name

		    if (preg_match_all( $host_match_regex, $buff, $matches )) {
			    $local_score = count($matches[0]) * 5;
			    $score += $local_score;
			    $log_res_obj->append($matches[0], $local_score);
		    }
	    }

	    /////////////////////////////////////////////////////////////////////////////
        // Get from file or ENV
        $phrases = [
        	// Asshole spammer
	        'FeedbackFormEU' => 25,
	        '#44\s*7598\s*509161#si' => 25,

	        // russian
	        'Виртуальное казино' => 25,
	        'URGENT TRANSFER' => 25,
	        'Фортуна' => 25,
	        'Плей Фортуна' => 25,
	        'where can i buy' => 25,
	        'levitra buy' => 25,
	        'azithromycin' => 25,
	        'vardenafil buy' => 25,
	        'probbox' => 25,
	        'levitrasale' => 25,
	        'doxycycline' => 25,
	        'PlayFortuna' => 25,
	        'СМОТРЕТЬ',
	        'СМОТРЕТЬ Фильм' => 25,

	        'Are You Purchasing' => 25,
	        'Welcome to my project' => 25,
	        'Attention Beneficiary' => 50,
	        'buyrealdocuments',
	        'Fake documents' => 25,
	        'Schreiben Sie mir bitte' => 25,
	        'good bonus for you' => 25,
	        '#good\s+bonus\s+for\s+you#' => 25,
	        '#bonus(es)?\s+(for|4)\s+you#' => 25,

	        'interested in your products',
	        '#increase the visitors?#',
	        'Bitcoin Brokers',
	        'more sales or customers',
	        'more sales',
	        'more customers',
	        'bestvisitors.icu',
	        'Brokers Bewertungen',
	        'Boost your website ranking',

	        // mkt
	        'quickly promote your website',
	        'no long term contracts',
	        'saving you some money',
	        'save money',
	        'earn money',
	        'Our Search Engine Optimization team',
	        'Our SEO team',

	        'Олимп Трейд',
	        'Биномо',
	        'зaработok в интеpнeтe',

	        // porn
	        'Top adult site',
	        'online porn',
	        'online porno',
	        'free porn',
	        'free p0rn',
	        'hardcore sex',
	        'henati sex',
	        'hentai sex',
	        'fat cock',
	        'breast lift',
	        'Lesbian',
	        '#Natural Tits?#si',
	        '#Lesbians?#si',
	        '#sex toys?#si',
	        '#girls? gets? fucked#si',

	        // games: https://mail.google.com/mail/u/0/#search/from%3Aorbisius/FMfcgxwCgpdRKKKrGqsnMHPXSmltxwQV
	        'best online games',
	        'best online ps4 games',
	        'game consoles',
	        'game directly from PSN store',
	        'PSN Store',
	        'buy and play the game',
	        'buy & play the game',
	        'gta 5',
	        'playstation 3',
	        'playstation 4',

	        'fast money',
        	'money fast',
        	'Day Loan',
	        'blockchain technology',
	        'make a profit',
        	'Pay Day Loan',
	        'Dear Sir',
	        'Dear Madame',
	        'Dear Sir/Madam',
	        'Dear Madam/Sir',
	        'Dear Web site owner',
	        'Dear Web owner',
	        '#Only \$\d+#si',
	        'based in India',
	        'I am Marketing Manager',
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
	        'long penis',
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
	        'buy cialis' => 50,
	        'buy viagra' => 50,
	        'online pharmacy' => 25,
	        'XXX movie' => 50,
	        'XXX movies' => 50,
	        'Top mp4 xxx' => 50,
	        'sex videos' => 50,
	        'Top xxx' => 50,
	        '100iki.ru' => 25,
	        'Eboek downloaden' => 25,
	        'E-boek downloaden' => 25,
	        'jamesGoots@' => 25,
	        'mexican pharmacy' => 25,
	        'mexican pharmacy no prescription needed' => 25,
	        'with no prescription' => 25,
	        'no prescription necessary' => 25,
	        '#fax.*?promotion#si' => 25,
	        'fax.promotion' => 25,
	        '#[\w\-]+\s+\d+\s*mg#si' => 25, // azithromycin 500mg
	        "#PS[:\s]*Don't just take my word for it#si",
	        '#\d+\-?Days?\s+Test\s+Drive#si', // 14-Day Test Drive
	        '#\d+\-?Days?\s+(free\s+)?Trial#si', // 14-Day free trial
        ];

	    $sites = [
		    'levitrasale.com',
		    'vardenafilbuy.com',
		    'doxycycline02.com',
	    ];

	    $white_listed_ips = [
	    ];

	    // score the IP too
	    $ips = [
	    ];

	    $blocked_ips = [];

	    if (!empty($this->remote_spam_definition_urls)) {
	    	foreach ($this->remote_spam_definition_urls as $url_rec) {
	    		$csv_data = orb_anti_spam_util::read_csv_file($url_rec['url']);

			    if (empty($csv_data)) {
				    continue;
			    }

			    foreach ($csv_data as $row) {
				    if ( empty( $row ) ) {
					    continue;
				    }

				    if ( empty( $row['phrase'] ) ) {
					    continue;
				    }

				    $phrase = $row['phrase'];

				    // Do some basic cleanup as we could have some extra characters from IP or URLs.
				    $phrase = trim($phrase, '/.\\? ');
				    $first_char = substr($phrase, 0, 1);

				    // Deactivate a rule by putting a char in front of it
				    if (in_array($first_char, [ '!', '-', ])) {
				    	continue;
				    }

				    $csv_score = empty( $row['score'] ) || $row['score'] <= 0 ? 5 : $row['score'];

				    if ( orb_anti_spam_util::is_ip( $phrase ) ) {
					    $blocked_ips[ $phrase ] = $csv_score;
					    continue;
				    }

				    if ( orb_anti_spam_util::is_domain( $phrase ) ) {
					    $sites[ $phrase ] = $csv_score;
					    continue;
				    }

				    $phrases[ $phrase ] = $csv_score;
			    }
		    }
	    }

	    $user_ip = orb_anti_spam_util::get_user_ip();

	    if (!empty($user_ip) && !empty($blocked_ips)) {
			foreach ($blocked_ips as $blocked_ip => $local_score) {
				// phrase is supplied as value, blocked ip is actually array index
				if (is_numeric($blocked_ip)) {
					$blocked_ip = $local_score;
					$local_score = 5;
				}

				// full match
				if ($_SERVER['REMOTE_ADDR'] == $blocked_ip) {
					$score += $local_score;
					$log_res_obj->append('blocked ip: ' . $blocked_ip, $local_score);
					break;
				}

				$partial_ip_match = '#^' . preg_quote($blocked_ip) . '#si';

				if (preg_match($partial_ip_match, $_SERVER['REMOTE_ADDR'])) {
					$score += $local_score;
					$log_res_obj->append('blocked partial ip: ' . $blocked_ip, $local_score);
					break;
				}
			}
	    }

        static $spam_file_data = null;

        if (is_null($spam_file_data) && !empty($this->params['spam_file']) && is_file($this->params['spam_file'])) {
        	$buff_raw = file_get_contents($this->params['spam_file'], LOCK_SH);
        	$spam_file_data = preg_split('#[\r\n]+#si', $buff_raw);
	        $spam_file_data = array_filter($spam_file_data);
        }

        $spam_file_data = empty($spam_file_data) ? [] : $spam_file_data;
        $phrases = array_merge($phrases, $spam_file_data, $sites);

        foreach ($phrases as $key => $phrase) {
	        $key = trim($key);
	        $phrase = trim($phrase);
        	$points = 5;

        	if (is_numeric($key)) {
				// phrase is supplied as value
	        } else { // the keyword has points specified explicitly.
        		if ($phrase > 0) {
        			$points = $phrase;
		        }

        		$phrase = $key;
	        }

        	$first_char = substr($phrase, 0, 1);

        	if (in_array($first_char, [ '#', '/', ] )) { // already quoted and ready to use regex
		        $regex = $phrase;
	        } else {
		        $phrase_qu = preg_quote( $phrase, '#' );
	            $regex = '#\b(' . $phrase_qu . ')\b#si';
	        }

	        // is the regex valid? skip
	        // @see https://stackoverflow.com/questions/4440626/how-can-i-validate-regex/12941133#12941133
	        // @see https://stackoverflow.com/questions/10778318/test-if-a-string-is-regex
	        if (@preg_match($regex, null) === false) {
		        continue;
	        }

	        if (preg_match_all( $regex, $buff,$matches )) {
		        $local_score = count($matches[0]) * $points;
		        $score += $local_score;
		        $log_res_obj->append($matches[0], $local_score);
	        }
        }

	    $this->scans[] = $log_res_obj;

        return $score;
    }

    public function get_scan_log() {
    	return $this->scans;
    }
}

class orb_anti_spam_util {
	/**
	 * @param string $str
	 * @return bool
	 */
	public static function is_domain($str) {
		$r = '#^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$#si';

		if (preg_match($r, $str)) {
			return true;
		}

		return false;
	}

	/**
	 * @param $ip
	 * @return bool
	 */
	public static function is_ip($ip) {
		if ( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			return true;
		}

		if ( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			return true;
		}

		// full or partial ip v4
		if (preg_match('#^\d+\.\d+\.\d+(\.\d+)?$#si', $ip)) {
			return true;
		}

		return false;
	}

	/**
	 * Return the user's home directory.
	 * orb_anti_spam_util::get_user_home()
	 * @see https://stackoverflow.com/questions/1894917/how-to-get-the-home-directory-from-a-php-cli-script
	 */
	public static function get_user_home() {
		// Cannot use $_SERVER superglobal since that's empty during UnitUnishTestCase
		// getenv('HOME') isn't set on Windows and generates a Notice.
		$home = getenv('HOME');

		if (!empty($home)) {
			// home should never end with a trailing slash.
			$home = rtrim($home, '/');
		} elseif (!empty($_SERVER['HOME'])) {
			$home = rtrim($_SERVER['HOME'], '\\/');
		} elseif (!empty($_SERVER['HOMEDRIVE']) && !empty($_SERVER['HOMEPATH'])) {
			// home on windows
			$home = $_SERVER['HOMEDRIVE'] . $_SERVER['HOMEPATH'];
			// If HOMEPATH is a root directory the path can end with a slash. Make sure
			// that doesn't happen.
			$home = rtrim($home, '\\/');
		} elseif (function_exists('posix_getuid')) {
			$os_uid = function_exists('posix_getuid') ? posix_getuid() : -1;
			$os_user_rec = function_exists('posix_getpwuid') ? posix_getpwuid($os_uid) : [];

			if (!empty($os_user_rec['dir'])) {
				$home = $os_user_rec['dir'];
			}
		}

		return empty($home) ? '' : $home;
	}

	/**
	 * Reads a CSV file and makes it into an associative array.
	 * orb_anti_spam_util::read_csv_file();
	 * https://www.php.net/manual/en/function.str-getcsv.php
	 * @link http://gist.github.com/385876
	 */
	public static function read_csv_file( $filename = '', $delimiter = ',' ) {
		if (preg_match('#^(s?ftps?|https?)://.{5,255}#si', $filename)) {
			// https://stackoverflow.com/questions/1894917/how-to-get-the-home-directory-from-a-php-cli-script
			$dirs = [];
			$home_dir = orb_anti_spam_util::get_user_home();

			if (empty($home_dir)) {
				return [];
			}

			$dirs[] = $home_dir;

			if (!empty($_SERVER['DOCUMENT_ROOT'])) {
				$dirs[] = dirname( $_SERVER['DOCUMENT_ROOT'] ); // 1 level up of doc root
				$dirs[] = $_SERVER['DOCUMENT_ROOT']; // doc root
				$dirs[] = $_SERVER['DOCUMENT_ROOT'] . '/wp-content';
			}

			$dirs[] = dirname(__FILE__); // 1 level up of doc root

			foreach ($dirs as $dir) {
				if (is_writable($dir)) {
					$root_dir = $dir;
					break;
				}
			}

			$target_dir = $root_dir . '/.ht_orbisius_anti_spam/data';
			$target_tmp_file = $target_dir . '/feed_' . microtime(true) . '.csv';
			$target_final_file = $target_dir . '/feed_' . sha1($filename) . '.csv';

			$dl_fresh = !file_exists($target_final_file) || abs(filemtime($target_final_file) - time()) > 4 * 3600;

			if ($dl_fresh) {
				try {
					if ( ! is_dir( dirname( $target_tmp_file ) ) ) {
						if ( ! mkdir( dirname( $target_tmp_file ), 0755, 1 ) ) {
							throw new Exception( "Cannot create target file's parent dir. Target file: " . $target_tmp_file );
						}
					}

					$fp = fopen( $target_tmp_file, 'wb' );

					if ( empty( $fp ) ) {
						throw new Exception( "Cannot open file for writing. Target file: " . $target_tmp_file );
					}

					flock( $fp, LOCK_EX );

					// https://stackoverflow.com/questions/6409462/downloading-a-large-file-using-curl
					$ch = curl_init( $filename );

					curl_setopt( $ch, CURLOPT_FILE, $fp );
					curl_setopt( $ch, CURLOPT_TIMEOUT, 90 );
					curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
					curl_setopt( $ch, CURLOPT_HEADER, 0 );
					curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 0 );
					curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0 );

					$data         = curl_exec( $ch );
					$error        = curl_error( $ch );
					$dbg          = curl_getinfo( $ch );
					$content_type = curl_getinfo( $ch, CURLINFO_CONTENT_TYPE );
					$status_code  = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
					curl_close( $ch );

					if ( $status_code != 200 ) {
						throw new Exception( "Invalid (non ok) response code received: " . $status_code );
					}

					if ( ! preg_match( '#text/(csv|\w+)#si', $content_type ) ) {
						throw new Exception( "Invalid CSV content file: " . $content_type );
					}

					flock( $fp, LOCK_UN );
					fclose( $fp );

					// We keep a tmp file so we can raneme this at the last moment so existing connections
					// will use the old file
					if (!hash_equals(sha1_file($target_final_file), sha1_file($target_tmp_file))){
						rename( $target_tmp_file, $target_final_file );
					}
				} catch ( Exception $e ) {
					return [];
				} finally {

				}
			}

			$filename = $target_final_file;

			// fetch file using wp curl or wget or linux curl
			// get user home
			// create dir /.anti_spam/data/some_feed.csv
			// parse file and set file
		} elseif ( ! file_exists( $filename ) || ! is_readable( $filename ) ) {
			return [];
		}

		$data   = [];
		$header = [];

		// In some cases (Windows/Linux) the line endings are not read correctly so we'll hint php to detect the line endings.
		$old_auto_detect_line_endings_flag = ini_get("auto_detect_line_endings");
		ini_set("auto_detect_line_endings", true);

		$handle = fopen( $filename, 'rb' );

		if (empty($handle)) {
			return [];
		}

		flock($handle, LOCK_SH);

		while ( ( $row = fgetcsv( $handle, 1024, $delimiter ) ) !== false ) {
			if (empty($row)) {
				continue;
			}

			$row = array_map('trim', $row );

			if (empty($row)) {
				continue;
			}

			// Empty lines could produce empty columns
			$row_alt_empty_check = array_filter($row);

			if (empty($row_alt_empty_check)) {
				continue;
			}

			if ( empty($header) ) {
				foreach ($row as $key => & $val) {
					$val = strtolower($val);
					$val = preg_replace('#[^\w]#si', '_', $val);
					$val = preg_replace('#\_+#si', '_', $val);
					$val = trim($val, ' _');
				}

				$header = $row;
			} else {
				// We'll use the first col as a primary ID so we can quickly search in js by preset id
				$first_col = reset($header); // preset_it
				$rec = array_combine( $header, $row );
				$primary_key = empty($rec[$first_col]) ? '' : $rec[$first_col];
				$data[$primary_key] = $rec;
			}
		}

		flock($handle, LOCK_UN);
		fclose( $handle );

		ini_set("auto_detect_line_endings", $old_auto_detect_line_endings_flag); // restore previous value

		return $data;
	}

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

	const CAST_INT = 2;
	const CAST_ABS_INT = 4;
	const CAST_IF_EXISTS = 8;

	/**
	 * Gets field from the params. The key can partially match internal vars.
	 * orb_anti_spam_util::get_field();
	 * @param string $field
	 * @param array $params
	 * @return string
	 */
	public static function get_field($field, $params = [], $default_val = '') {
		if (empty($field)) {
			return $default_val;
		}

		if (empty($params)) {
			if (php_sapi_name() == 'cli') {
				$params = orb_anti_spam_util::parse_arguments();
			} elseif (!empty($_REQUEST)) {
				$params = $_REQUEST;
			}
		}

		if (empty($params)) {
			return $default_val;
		}

		$params = (array) $params; // jic.
		$mutliple_fields = [];

		if (is_array($field)) {
			$mutliple_fields = $field;
		} elseif (is_scalar($field)) {
			$mutliple_fields = preg_split( '#([\|\/\;\,\s]+)#si', $field);
		} else {
			throw new Exception("Bad variable type for field");
		}

		foreach ($mutliple_fields as $one_option) {
			// the value may have been passed as an empty string -> use default
			if (isset($params[$one_option])) {
				return empty($params[$one_option]) ? $default_val : $params[$one_option];
			}
		}

		$params = array_filter($params); // rm empty ones.
		$keys = array_keys($params);
		rsort($keys); // keys with longer names will appear first so target_ftp_user shows up first in case ftp_server is passed.

		// We want the longer fields to appear first so they match in the regex.
		// No!: we'll check the fields in the order they are supplied
		//usort($mutliple_fields, 'orb_anti_spam_util::sortByStrLength');
		//$mutliple_fields = array_reverse($mutliple_fields);

		// Let's join all fields like this so the sanitiation won't affect the issue.
		$field = join('__PIPE__', $mutliple_fields);
		$field = preg_replace('#^[^\w]+#si', '', $field); // rm leading non-alpha chars in case I put $some_name
		$field_esc = preg_quote($field, '#');
		$field_esc = str_replace( [ '__PIPE__' ], '|', $field_esc); // the field can be test_name or test-name
		$field_esc = str_replace( [ '-', '_' ], '[\-\_]+', $field_esc); // the field can be test_name or test-name

		$actual_field_name_arr = preg_grep('#[\-\_]*' . $field_esc . '$#si', $keys); // optionally prefixed by - or --
		$actual_field_name = empty($actual_field_name_arr) ? $field : array_shift($actual_field_name_arr);

		if (is_scalar($default_val)
		    && is_numeric($default_val)
		    && ( ($default_val & self::CAST_INT) || ($default_val & self::CAST_ABS_INT)) ) {
			if (isset($params[$actual_field_name])) {
				$val = empty($params[$actual_field_name]) ? 0 : (int) $params[$actual_field_name];

				if ($default_val & self::CAST_ABS_INT) {
					$val = abs($val);
				}
			} else {
				$val = '';
			}
		} else {
			$val = empty($params[$actual_field_name]) ? $default_val : $params[$actual_field_name];
		}

		return $val;
	}

	/**
	 * Parses command line arguments. For some weird reason getopts breaks sometimes.
	 * The original code has been modified to work with long arguments.
	 * orb_anti_spam_util::parse_arguments();
	 * @todo arrays --var1=test1 --var1=test2
	 *
	 * @return array
	 *
	 * @see http://stackoverflow.com/questions/6553239/is-there-a-complete-command-line-parser-for-php
	 * @see https://gist.github.com/magnetik/2959619
	 */
	public static function parse_arguments( $my_arg = [] ) {
		$cmd_args = array();
		$skip = array();

		global $argv;
		$new_argv = empty( $my_arg ) ? $argv : $my_arg;

		if ( !empty( $new_argv ) ) {
			array_shift( $new_argv ); // skip arg 0 which is the filename
		}

		foreach ( $new_argv as $idx => $arg ) {
			if ( in_array( $idx, $skip ) ) {
				continue;
			}

			$arg = trim($arg);
			$arg = trim($arg, "\"' ");
			$arg = preg_replace( '#[\s\'"]*\=[\s\'"]*#si', '=', $arg );
			$arg = preg_replace( '#(--+[\w-]+)\s+[^=]#si', '${1}=', $arg );

			if ( substr($arg, 0, 2) == '--' ) {
				$eqPos = strpos($arg, '=');

				if ($eqPos === false) {
					$key = trim($arg, '- ');
					$val = isset($cmd_args[$key]);

					// We handle case: --user-id 123 -> this is a long option with a value passed.
					// the actual value comes as the next element from the array.
					// We check if the next element from the array is not an option.
					if ( isset( $new_argv[ $idx + 1 ] ) && ! preg_match('#^-#si', $new_argv[ $idx + 1 ] ) ) {
						$cmd_args[ $key ] = trim( $new_argv[ $idx + 1 ] );
						$skip[] = $idx;
						$skip[] = $idx + 1;
						continue;
					}

					$cmd_args[$key] = $val;
				} else {
					$key = substr($arg, 2, $eqPos - 2);
					$val = substr($arg, $eqPos + 1);

					if (!empty($cmd_args[$key])) { // the value already exists so this must be treated as an array
						$cmd_args[$key] = (array) $cmd_args[$key];
						$cmd_args[$key][] = $val;
					} else {
						$cmd_args[$key] = $val;
					}
				}
			} else if (substr($arg, 0, 1) == '-') {
				if (substr($arg, 2, 1) == '=') {
					$key = substr($arg, 1, 1);
					$val = substr($arg, 3);

					if (!empty($cmd_args[$key])) { // the value already exists so this must be treated as an array
						$cmd_args[$key] = (array) $cmd_args[$key];
						$cmd_args[$key][] = $val;
					} else {
						$cmd_args[$key] = $val;
					}
				} else {
					$chars = str_split(substr($arg, 1));

					foreach ($chars as $char) {
						$key = $char;
						$cmd_args[$key] = isset($cmd_args[$key]) ? $cmd_args[$key] : true;
					}
				}
			} else {
				$cmd_args[] = $arg;
			}
		}

		return $cmd_args;
	}

	/**
	 * @return string
	 */
	public static function get_user_ip() {
		return empty($_SERVER['REMOTE_ADDR']) ? '' : $_SERVER['REMOTE_ADDR'];
	}
}


class orb_anti_spam_result {
	const OVERRIDE_FLAG = 2;
	const DONT_OVERRIDE_FLAG = 4;
	const CONVERT_DATA_KEYS_TO_LOWER_CASE = 8;
	const CONVERT_DATA_KEYS_TO_UPPER_CASE = 16;

	// I put them as public even though I need them private.
	// reason: private fields don't appear in a JSON output
	public $msg = '';
	public $code = '';
	public $status = 0;
	public $data = array();

	/**
	 * Populates the internal variables from contr params.
	 *
	 * @param int/str/array $json
	 */
	public function __construct( $json = '' ) {
		if ( ! empty( $json ) ) {
			if ( is_scalar( $json ) ) {
				if ( is_bool( $json ) || is_numeric( $json ) ) {
					$this->status = abs( (int) $json );
				} elseif ( is_string( $json ) ) {
					$json = json_decode( $json, true );
				}
			} elseif ( is_object( $json ) ) {
				$json = (array) $json;
			}

			if ( is_array( $json ) ) {
				foreach ( $json as $key => $value ) {
					// Some recognized keys' values will go as internal fields & the rest as data items.
					if ( preg_match( '#^(status|msg|code|data)$#si', $key ) ) {
						$this->$key = $value;
					} else {
						$this->data[ $key ] = $value;
					}
				}
			}
		}
	}

	/**
	 * Cool method which is nicer than checking for a status value.
	 * @return bool
	 */
	public function isSuccess() {
		return ! empty( $this->status );
	}

	/**
	 * Cool method which is nicer than checking for a status value.
	 * @return bool
	 */
	public function isError() {
		return ! $this->isSuccess();
	}

	public function status( $new_status = null ) {
		if ( ! is_null( $new_status ) ) {
			$this->status = (int) $new_status; // we want 0 or 1 and not just random 0, 1 and true or false
		}

		return $this->status;
	}

	/**
	 * returns or sets a message
	 *
	 * @param str $msg
	 *
	 * @return str
	 */
	public function code( $code = '' ) {
		if ( ! empty( $code ) ) {
			$code = preg_replace( '#[^\w\d]#si', '_', $code );
			$code = trim( $code, '_- ' );
//			$code = App_Sandbox_String_Util::singlefyChars( $code );
			$code       = strtoupper( $code );
			$this->code = $code;
		}

		return $this->code;
	}

	/**
	 * Alias to msg
	 *
	 * @param str $new_message
	 *
	 * @return str
	 */
	public function message( $new_message = null ) {
		return $this->msg( $new_message );
	}

	/**
	 * returns or sets a message
	 *
	 * @param str $msg
	 *
	 * @return str
	 */
	public function msg( $msg = '' ) {
		if ( ! empty( $msg ) ) {
			$this->msg = QS_App_WP5_String_Util::trim( $msg );
		}

		return $this->msg;
	}

	/**
	 * Getter and setter
	 *
	 * @param type $new_status
	 *
	 * @return bool
	 */
	public function success( $new_status = null ) {
		$this->status( $new_status );

		return ! empty( $this->status );
	}

	/**
	 * Getter and setter
	 *
	 * @param type $new_status
	 *
	 * @return bool
	 */
	public function error( $new_status = null ) {
		$this->status( $new_status );

		return empty( $this->status );
	}

	/**
	 *
	 * @param mixed $key_or_records
	 * @param mixed $value
	 *
	 * @return mixed
	 */
	public function data( $key = '', $val = null ) {
		if ( is_array( $key ) ) { // when we pass an array -> override all
			if ( ! empty( $val ) && ( self::OVERRIDE_FLAG & $val ) ) { // full data overriding.
				$this->data = $key;
			} else {
				$this->data = empty( $this->data ) ? $key : array_merge( $this->data, $key );
			}
		} elseif ( ! empty( $key ) ) {
			if ( ! is_null( $val ) ) { // add/update a value
				$this->data[ $key ] = $val;
			}

			return isset( $this->data[ $key ] ) ? $this->data[ $key ] : '';
		} else { // nothing return all data
			$val = $this->data;
		}

		return $val;
	}

	/**
	 * @param $key
	 * @param mixed $val
	 */
	public function append( $key, $val = null) {
		// Let's simplify things. If it's a simple one element array why not get that field.
		if (is_array($key) && count($key) == 1) {
			$key = array_shift($key);
		}

		$this->data[] = [ 'key' => $key, 'val' => $val ];
	}

	/**
	 * Removes one or more keys from the data array.
	 *
	 * @param type $key
	 */
	public function deleteKey( $key = '' ) {
		$key_arr = (array) $key;

		foreach ( $key_arr as $key_to_del ) {
			unset( $this->data[ $key_to_del ] );
		}
	}

	/**
	 * Renames a key in case the receiving api exects a given key name.
	 *
	 * @param str $key
	 * @param str $new_key
	 */
	public function renameKey( $key, $new_key ) {
		if ( empty( $key ) || empty( $new_key ) ) {
			return;
		}

		$val = $this->data( $key ); // get old val
		$this->deleteKey( $key );
		$this->data( $new_key, $val );
	}

	/**
	 * Extracts data from the params and populates the internal data array.
	 * It's useful when storing data from another request
	 *
	 * @param str/array/obj $json
	 * @param int $flag
	 */
	public function populateData( $json, $flag = self::DONT_OVERRIDE_FLAG ) {
		if ( empty( $json ) ) {
			return false;
		}

		if ( is_string( $json ) ) {
			$json = json_decode( $json, true );
		} else if ( is_object( $json ) ) {
			$json = (array) $json;
		}

		if ( is_array( $json ) ) {
			foreach ( $json as $key => $value ) {
				if ( isset( $this->data[ $key ] ) && ( $flag & self::DONT_OVERRIDE_FLAG ) ) {
					continue;
				}

				// In case 'ID' we have 'id' in the data
				if ( is_array( $value ) ) {
					if ( $flag & self::CONVERT_DATA_KEYS_TO_LOWER_CASE ) {
						$value = array_change_key_case( $value, CASE_LOWER );
					}

					if ( $flag & self::CONVERT_DATA_KEYS_TO_UPPER_CASE ) {
						$value = array_change_key_case( $value, CASE_UPPER );
					}
				}

				// In case 'ID' we want to have it as 'id'.
				if ( ! is_numeric( $key ) && ( $flag & self::CONVERT_DATA_KEYS_TO_LOWER_CASE ) ) {
					$key = strtolower( $key );
				}

				$this->data[ $key ] = $value;
			}
		}
	}

	public function __set( $name, $value ) {
		$this->$name = $value;
	}

	/**
	 * Returns member data or a key from data. It's easier e.g. $data_res->output
	 *
	 * @param string $name
	 *
	 * @return mixed|null
	 */
	public function __get( $name ) {
		if ( ! empty( $this->$name ) ) {
			return $this->$name;
		}

		if ( isset( $this->data[ $name ] ) ) {
			return $this->data[ $name ];
		}

		return null;
	}

	/**
	 * Checks if a data property exists
	 *
	 * @param string $key Property key
	 */
	public function __isset( $key ) {
		return ! is_null( $this->__get( $key ) );
	}

	public function __call( $name, $arguments ) {

	}

	/**
	 * In case this is used in a string context it should return something meaningful.
	 * @return string
	 */
	public function __toString() {
		$json_str = json_encode( $this, JSON_PRETTY_PRINT );

		// returns false/empty if non uft8 encoded
		if ( empty( $json_str ) ) {
			if ( class_exists( 'QS_App_WP5_String_Util' ) ) {
				$json_str = QS_App_WP5_String_Util::jsonEncode( $this );
			} else {
				$json_str = "{ status: " . ( $this->status() ? 1 : 0 ) . ', msg : "__qs_result_to_str__" }';
				//$json_str = "{ status: ". $this->status() ? 'Success: ' . $this->msg() : 'Error: ' . $this->msg();
			}
		}

		return $json_str;
	}

	/**
	 * Removes data
	 */
	public function clearData() {
		$this->data = [];
	}
}

