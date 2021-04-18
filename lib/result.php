<?php

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