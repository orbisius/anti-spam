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

