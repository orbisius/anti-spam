<?php

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

	/**
	 * @return bool
	 */
	public static function is_dev_env() {
		return !self::is_live_env();
	}

	/**
	 * @return bool
	 */
	public static function is_live_env() {
		$live_mode = empty($_SERVER['DEV_ENV']);
		return $live_mode;
	}
}
