<?php

require_once __DIR__ . '/Defensio.php';

/**
 * @package Defensio
 * @todo add speicific comment ID to EventLog::log()s
 */
class Defensio extends Plugin
{
	const CHECK_FREQUENCY = 300; // 5 min
	const MAX_COMMENT_DAYS = 30;
	const COMMENT_STATUS_QUEUED = 9;

	const DEFENSIO_CLIENT_ID = 'Habari Defensio Plugin | 2.0 | Jeffrey Bush | jeff@coderforlife.com';

	const OPTION_API_KEY = 'defensio__api_key';
	const OPTION_FLAG_SPAMINESS = 'defensio__spaminess_flag';
	const OPTION_DELETE_SPAMINESS = 'defensio__spaminess_delete';
	const OPTION_ANNOUNCE_POSTS = 'defensio__announce_posts';
	const OPTION_AUTO_APPROVE = 'defensio__auto_approve';
	const OPTION_PROFANITY_FILTER_AUTHOR = 'defensio__profanity_filter_author';
	const OPTION_PROFANITY_FILTER_CONTENT = 'defensio__profanity_filter_content';

	private $defensio;


	////////// Basic Setup and Initialization //////////

	/**
	 * Setup defaults on activation. Don't overwrite API key if it's already there. Start Defensio Queue.
	 */
	public function action_plugin_activation()
	{
		Session::notice( _t('Please set your Defensio API Key in the configuration.', 'defensio') );
		if ( !Options::get(self::OPTION_API_KEY) ) {
			Options::set( self::OPTION_API_KEY, '' );
		}
		Options::set(self::OPTION_FLAG_SPAMINESS, 80); // WordPress default
		Options::set(self::OPTION_DELETE_SPAMINESS, 99);
		Options::set(self::OPTION_ANNOUNCE_POSTS, true);
		Options::set(self::OPTION_AUTO_APPROVE, false);
		Options::set(self::OPTION_PROFANITY_FILTER_AUTHOR, false);
		Options::set(self::OPTION_PROFANITY_FILTER_CONTENT, false);
		
		CronTab::add_cron(array(
			'name' => 'defensio_queue',
			'callback' => 'defensio_queue',
			'increment' => self::CHECK_FREQUENCY,
			'cron_class' => CronJob::CRON_PLUGIN,
			'description' => _t('Scan comments with Defensio that were pending and failed queued the first time', 'defensio'),
		));
	}

	/**
	 * Stop Defensio Queue.
	 */
	function action_plugin_deactivation()
	{
		CronTab::delete_cronjob('defensio_queue');
	}

	/**
	 * Setup the Defensio API on Habari initialization. Also, make sure to register the dashboard template.
	 * @todo move text domain loading to only admin.
	 */
	public function action_init()
	{
		$this->defensio = new DefensioAPI( Options::get( self::OPTION_API_KEY ), self::DEFENSIO_CLIENT_ID );
		$this->load_text_domain( 'defensio' );
		$this->add_template( 'dashboard.block.defensio', __DIR__ . '/dashboard.block.defensio.php' );
		$this->add_template( 'dashboard.block.defensio_extended', __DIR__ . '/dashboard.block.defensio_extended.php' );
	}


	////////// Configuration //////////

	/**
	 * Implement the simple plugin configuration.
	 * @return FormUI The configuration form
	 */
	public function configure()
	{
		$spaminess_keys = $spaminess_values = range(0, 95, 5);
		foreach ($spaminess_keys as &$x) { $x .= '%'; }
		$spaminess_opts = array_combine(array_merge($spaminess_keys, array('99%', 'Never')), array_merge($spaminess_values, array(99, 100)));
		
		$ui = new FormUI( 'defensio' );

		// add a text control for the address you want the email sent to
		$api_key = $ui->append(
				'text',
				'api_key',
				'option:' . self::OPTION_API_KEY,
				_t('Defensio API Key: ', 'defensio')
			);
		$api_key->add_validator( 'validate_required' );
		$api_key->add_validator( array( $this, 'validate_api_key' ) );

		// min spaminess flag
		$spaminess_flag = $ui->append(
				'select',
				'min_spaminess_flag',
				'option:' . self::OPTION_FLAG_SPAMINESS,
				_t('Minimum Spaminess to Flag as Spam: ', 'defensio')
			);
		$spaminess_flag->options = $spaminess_opts;
		$spaminess_flag->add_validator( 'validate_required' );

		// min spaminess for automatic deletion
		$spaminess_delete = $ui->append(
				'select',
				'min_spaminess_delete',
				'option:' . self::OPTION_DELETE_SPAMINESS,
				_t('Minimum Spaminess to Automatically Delete: ', 'defensio')
			);
		$spaminess_delete->options = $spaminess_opts;
		$spaminess_delete->add_validator( 'validate_required' );


		// checkboxes
		$announce_posts = $ui->append( 'checkbox', 'announce_posts', 'option:' . self::OPTION_ANNOUNCE_POSTS,           _t('Announce New Posts To Defensio: ',          'defensio') );
		$auto_approve   = $ui->append( 'checkbox', 'auto_approve',   'option:' . self::OPTION_AUTO_APPROVE,             _t('Automatically Approve Non-Spam Comments: ', 'defensio') );
		$filter_author  = $ui->append( 'checkbox', 'filter_author',  'option:' . self::OPTION_PROFANITY_FILTER_AUTHOR,  _t('Filter Profanity in Comment Author: ',      'defensio') );
		$filter_content = $ui->append( 'checkbox', 'filter_content', 'option:' . self::OPTION_PROFANITY_FILTER_CONTENT, _t('Filter Profanity in Comment Content: ',     'defensio') );


		$register = $ui->append(
				'static',
				'register',
				'<a href="http://defensio.com/signup">' . _t('Get A New Defensio API Key.', 'defensio') . '</a>'
			);

		$ui->append( 'submit', 'save', _t( 'Save', 'defensio' ) );
		$ui->on_success( array($this, 'formui_submit') );
		return $ui->get();
	}

	/**
	 * Handle the form submition and save options
	 * @param FormUI $form The FormUI that was submitted
	 */
	public function formui_submit( FormUI $form )
	{
		Session::notice( _t('Defensio options saved.', 'defensio') );
		$form->save();
	}

	/**
	 * Trims a hostname so that it is in a standardized format, removing http://, https://, or www. from the beginning of it.
	 * @param string $host The hostname to trim
	 * @return string The trimmed hostname
	 */
	private static function trim_hostname($host)
	{
		$host = trim($host);
		if (strpos($host, 'http://') === 0)			{ $host = substr($host, 7); }
		else if (strpos($host, 'https://') === 0)	{ $host = substr($host, 8); }
		if (strpos($host, 'www.') === 0)			{ $host = substr($host, 4); }
		return $host;
	}

	/**
	 * FormUI validator to validate the entered API key with Defensio.
	 * @param string $key The API key to validate.
	 * @return array The error message if validation failed, or blank array if successful.
	 */
	public function validate_api_key( $key )
	{
		$host = self::trim_hostname( Site::get_url( 'hostname' ) );
		$defensio = new DefensioAPI( $key, self::DEFENSIO_CLIENT_ID );
		list( $errcode, $xml ) = $defensio->getUser();
		if ( $errcode == 200 && $xml->status == 'success' ) {
			return self::trim_hostname( $xml->{'owner-url'} ) == $host ? array() :
				array(_t('Sorry, the Defensio API key <b>%s</b> is not registered for this site (%s).', array( $key, $host ), 'defensio'));
		}
		return array(_t('Sorry, the Defensio API key <b>%s</b> is invalid. Please check to make sure the key is entered correctly. Defensio said: "%s"', array( $key, $xml->message ), 'defensio'));
	}
	
	
	////////// Dashboard Block //////////
	
	/**
	 * Add the blocks this plugin provides to the list of available blocks
	 * @param array $block_list An array of block names, indexed by unique string identifiers
	 * @return array The altered array
	 */
	public function filter_block_list( $block_list )
	{
		if (User::identify()->can('manage_all_comments')) {
			$block_list['defensio'] = _t( 'Defensio', 'defensio' );
			$block_list['defensio_extended'] = _t( 'Defensio Extended', 'defensio_extended' );
		}
		return $block_list;
	}
	
	/**
	 * Return a list of blocks that can be used for the dashboard
	 * @param array $block_list An array of block names, indexed by unique string identifiers
	 * @return array The altered array
	 */
	public function filter_dashboard_block_list( $block_list )
	{
		$block_list['defensio'] = _t( 'Defensio', 'defensio' );
		$block_list['defensio_extended'] = _t( 'Defensio Extended', 'defensio_extended' );
		return $block_list;
	}

	/**
	 * Produce the content for the Defensio block
	 * @param Block $block The block object
	 * @param Theme $theme The theme that the block will be output with
	 */
	public function action_block_content_defensio( $block, Theme $theme )
	{
		$block->link = URL::get('admin', array('page' => 'comments'));

		$stats = $this->defensio_stats();
		// show an error in the dashboard if Defensio returns a bad response.
		if ( is_string($stats) ) { $block->error_msg = $stats; return; }

		$block->error_msg = null;
		$block->accuracy        = ((string)$stats->accuracy) * 100.0;
		$block->spam            = ((string)$stats->unwanted->spam) * 1;
		$block->malicious       = ((string)$stats->unwanted->malicious) * 1;
		$block->legitimate      = ((string)$stats->legitimate->total) * 1;
		$block->false_negatives = ((string)$stats->{'false-negatives'}) * 1;
		$block->false_positives = ((string)$stats->{'false-positives'}) * 1;
		$block->learning        =  (string)$stats->learning == 'true';
		$block->learning_status =  (string)$stats->{'learning-status'};
	}

	/**
	 * Produce the content for the Defensio Extended block
	 * @param Block $block The block object
	 * @param Theme $theme The theme that the block will be output with
	 */
	public function action_block_content_defensio_extended( $block, Theme $theme )
	{
		$block->link = URL::get('admin', array('page' => 'comments'));

		$stats = $this->defensio_stats();
		// show an error in the dashboard if Defensio returns a bad response.
		if ( is_string($stats) ) { $block->error_msg = $stats; return; }

		$block->error_msg = null;
		$block->charts = array(
			'recent-accuracy'  => (string)$stats->{'chart-urls'}->{'recent-accuracy' },
			'total-unwanted'   => (string)$stats->{'chart-urls'}->{'total-unwanted'  },
			'total-legitimate' => (string)$stats->{'chart-urls'}->{'total-legitimate'},
		);
		
		$data = array();
		foreach ($stats->data->datum as $datum) {
			$data[] = array(
				'date'            =>  (string)$datum->date, // Y-m-d
				'accuracy'        => ((string)$datum->accuracy) * 100.0,
				'unwanted'        => ((string)$datum->unwanted) * 1,
				'legitimate'      => ((string)$datum->legitimate) * 1,
				'false-positives' => ((string)$datum->{'false-positives'}) * 1,
				'false-negatives' => ((string)$datum->{'false-negatives'}) * 1,
			);
		}
		
		// to get arrays of each field:
		// $date            = array_map(create_function('$x', 'return $x[\'date\'];'           ), $data);
		// $accuracy        = array_map(create_function('$x', 'return $x[\'accuracy\'];'       ), $data);
		// $unwanted        = array_map(create_function('$x', 'return $x[\'unwanted\'];'       ), $data);
		// $legitimate      = array_map(create_function('$x', 'return $x[\'legitimate\'];'     ), $data);
		// $false_positives = array_map(create_function('$x', 'return $x[\'false-positives\'];'), $data);
		// $false_negatives = array_map(create_function('$x', 'return $x[\'false-negatives\'];'), $data);
	}
	
	/**
	 * Get the basic Defensio stats.
	 * @return mixed The stats as SimpleXMLElement or a string with an error message.
	 */
	private function defensio_stats()
	{
		if ( Cache::has( 'defensio_stats' ) ) {
			$stats = simplexml_load_string( Cache::get( 'defensio_stats' ) );
		}
		else {
			list( $errcode, $stats ) = $this->defensio->getBasicStats();
			if ( $errcode != 200 || (string)$stats->status != 'success' ) {
				$msg = "Defensio error while getting stats: $errcode $stats->status $stats->message";
				EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
				return $msg;
			}
			Cache::set( 'defensio_stats', $stats->asXML() );
		}

		return $stats;
	}

	/**
	 * Get the extended Defensio stats given a date range.
	 * @param mixed $from int with Unix timestamp or string parsable by strtotime
	 * @param mixed $to int with Unix timestamp, string parsable by strtotime, or if not provided 30 days after from
	 * @return mixed The stats as SimpleXMLElement or a string with an error message.
	 */
	private function defensio_extended_stats( $from, $to = null )
	{
		// convert the 'from' time
		if ( is_string( $from ) ) { $from = strtotime( $from ); }
		$from = min( $from, time() );
		$from = date( 'Y-m-d', $from );
		
		// convert the 'to' time
		if ( is_null( $to ) ) { $to = strtotime( '+30 days', $from ); }
		else if ( is_string( $to ) ) { $to = strtotime( $to ); }
		$to = max( min( $to, time() ), $from );
		$to = date( 'Y-m-d', $to );
		
		list( $errcode, $stats ) = $this->defensio->getExtendedStats(array( 'from' => $from, 'to' => $to ));
		if ( $errcode != 200 || (string)$stats->status != 'success' ) {
			$msg = "Defensio error while getting extended stats: $errcode $stats->status $stats->message";
			EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			return $msg;
		}

		return $stats;
	}

	/**
	 * Get the extended Defensio stats for the last 30 days.
	 * @todo display somewhere
	 * @return mixed The stats as SimpleXMLElement or a string with an error message.
	 */
	private function defensio_recent_extended_stats()
	{
		if ( Cache::has( 'defensio_extended_stats' ) ) {
			$stats = simplexml_load_string( Cache::get( 'defensio_extended_stats' ) );
		}
		else {
			$stats = $this->defensio_extended_stats( strtotime('-30 days'), time() );
			if ( is_string($stats) ) {
				return $stats;
			}
			Cache::set( 'defensio_extended_stats', $stats->asXML() );
		}
		
		return $stats;
	}
	

	////////// Profanity Filtering //////////
	
	/**
	 * Filters the comment content for profanity if the user has enabled it
	 * @param string $comment The unfiltered content of the comment
	 * @param Comment $comment The comment being filtered
	 * @return string The content, filtered for profanity if the option is set
	 */
	public function filter_comment_content_out( $content, Comment $comment )
	{
		if ( Options::get( self::OPTION_PROFANITY_FILTER_CONTENT ) && $comment->info->defensio_profanity_match ) {
			$content = $this->defensio_profanity_filter( $content );
		}
		return $content;
	}

	/**
	 * Filters the comment author name for profanity if the user has enabled it
	 * @param string $comment The unfiltered author name of the comment
	 * @param Comment $comment The comment being filtered
	 * @return string The author name, filtered for profanity if the option is set
	 */
	public function filter_comment_name_out( $name, Comment $comment )
	{
		if ( Options::get( self::OPTION_PROFANITY_FILTER_AUTHOR ) ) {
			$name = $this->defensio_profanity_filter( $name );
		}
		return $name;
	}
	
	/**
	 * Filter out profanity with the Defensio.
	 * @param mixed $data string with text to filter or an array of strings to filter
	 * @return mixed The results of the filter, in the same format as given to the function. If there is an error the original data is returned.
	 */
	public function defensio_profanity_filter( $data )
	{
		if ( is_string($data) ) {
			$in = array( 'text' => $data );
		}
		else {
			// convert array names to xml-compatible element names
			$in = array();
			$map = array();
			foreach ( $data as $key => $value ) {
				$key_xml = $key;
				$count = count($key);
				for ($i = 0; $i < $count; ++$i) {
					if (!ctype_alnum($key_xml[$i]))
						$key_xml[$i] = '_';
				}
				$a = $key_xml[0];
				if (!ctype_alpha($a) || ($a == 'x' || $a == 'X') && stripos($key_xml, 'xml') === 0) {
					$key_xml = 'text_'.$key_xml;
				}
				$in[$key_xml] = $value;
				$map[$key_xml] = $key;
			}
		}
		
		// send data
		list( $errcode, $filtered ) = $this->defensio->postProfanityFilter( $in );
		if ( $errcode != 200 || (string)$filtered->status != 'success' ) {
			$msg = "Defensio error while running profanity filter: $errcode $filtered->status $filtered->message";
			EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			return $data;
		}
		
		// convert back to input format
		if ( is_string($data) )
			return (string)$filtered->filtered->text;
		$out = array();
		foreach ( $map as $key_xml => $key )
			$out[$key] = (string)$filtered->filtered->$key_xml;
		return $out;
	}
	
	
	////////// Comment Scanning //////////
	
	/**
	 * Whenever a comment is added, set it to be scanned by Defensio.
	 * @param Comment $comment The comment object to scan
	 */
	public function action_comment_insert_after( Comment $comment )
	{
		$this->defensio_post_comment( $comment, User::identify() );
		Session::notice( _t('Your comment is being scanned for spam.', 'defensio') );
	}

	/**
	 * The Defensio polling queue. Checks queued comments:
	 *  * removes them from the queue if they have been there for more than 30 days
	 *  * removes them is the pending asynchronous result is complete
	 *  * re-submits a request if the original failed
	 * This runs every 5 minutes.
	 * @param bool $cron_result The cron result, which is simply ignored and returned
	 * @return bool The given cron result, defaulting to true
	 */
	public function filter_defensio_queue( $cron_result = true )
	{
		$comments = Comments::get( array('status' => self::COMMENT_STATUS_QUEUED) );
		foreach( $comments as $comment ) {
			if ( self::comment_age( $comment ) > self::MAX_COMMENT_DAYS ) {
				$msg = "Defensio comment submission was pending or failed for 30 days. Will not try again.";
				EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			}
			else if ( isset($comment->info->defensio_signature) ) {
				
				// check pending asynchronous result
				list( $errcode, $result ) = $this->defensio->getDocument( $comment->info->defensio_signature );
				$status = (string)$result->status;
				if ( $errcode != 200 || ( $status != 'success' && $status != 'pending' ) ) {
					$msg = "Defensio error while getting comment results: $errcode $status $result->message\nWill try again.";
					EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
				}
				else if ( $status == 'success' ) {
					$this->defensio_update_comment( $comment, $result );
				}
				else {
					// else still pending
					EventLog::log( 'Defensio Queue: Document still pending', 'debug', 'plugin', 'Defensio' );
				}
				
			}
			else {
				
				// resubmit failed attempt
				EventLog::log( 'Defensio Queue: Retrying failed attempt', 'debug', 'plugin', 'Defensio' );
				$this->defensio_post_comment( $comment, User::get_by_id($comment->info->user_id) );
				
			}
		}
		return $cron_result;
	}

	/**
	 * Posts a comment to Defensio and updates it with any information. If it is unsuccessfully submitted
	 * then its status is set to queued and a user_id is added to its information for repeated attempts.
	 * For successes, the Defensio signature is added to the information. If the scan is still pending,
	 * its status is set to queued, otherwise it is sent to defensio_update_comment which will setup the
	 * remaining Defensio properties and adjust the property.
	 * @param Comment $comment The comment to submit
	 * @param mixed $user Either a User object or false representing the comment's author
	 */
	private function defensio_post_comment( Comment $comment, $user )
	{
		// setup data to post
		$params = array(
			'platform' => 'habari',
			'type' => strtolower( $comment->typename ), // one of: comment*, trackback*, pingback*, article, wiki, forum, other, test
			'async' => 'true',
			// @todo add callback
			// 'async-callback' => ...
			
			// @todo fill these in
			//'browser-cookies' => ...
			//'browser-javascript' => ...

			'parent-document-date' => $comment->post->pubdate->format( 'Y-m-d' ),
			'parent-document-permalink' => $comment->post->permalink,

			'author-name' => $comment->name,
			'author-ip' => is_string( $comment->ip ) && strpos( $comment->ip, '.' ) > 0 ? $comment->ip : long2ip( $comment->ip ),
			'document-permalink' => $comment->post->permalink.'#comment-'.$comment->id,
			//'title' => ... // comments have no title
			'content' => $comment->content,
		);
		
		// set HTTP header fields
		if ( isset( $_SERVER['HTTP_REFERER'] ) ) { $params['referrer'] = $_SERVER['HTTP_REFERER']; }
		$http_headers = array();
		foreach ( $_SERVER as $key => $value ) {
			if ( strpos($key, 'HTTP_') === 0 ) {
				$http_headers[substr($key, 5)] = $value;
			}
			else if ( $key == 'CONTENT_TYPE' || $key == 'CONTENT_LENGTH' ) { 
				$http_headers[$key] = $value;
			}
		}
		if (is_callable('apache_request_headers')) {
			$headers = @apache_request_headers();
		}
		else if (is_callable('getallheaders')) {
			$headers = @getallheaders();
		}
		else {
			$headers = false;
		}
		if ($headers !== false) {
			foreach ( $headers as $key => $value ) {
				$http_headers[str_replace('-', '_', strtoupper($key))] = $value;
			}
		}
		$http_headers_text = '';
		foreach ( $http_headers as $key => $value ) {
			$http_headers_text .= "$key: $value\n";
		}
		$params['http-headers'] = trim( $http_headers_text, "\n" );

		// set additional/conditional fields
		if ( $comment->email ) { $params['author-email'] = $comment->email; }
		if ( $comment->url )   { $params['author-url']   = $comment->url;   }
		if ( $user instanceof User && $user->id != 0 ) {
			$params['author-logged-in'] = $user->loggedin ? 'true' : 'false';
			// @todo test for administrator, editor, etc. as well
			$params['author-trusted'] = $user->loggedin ? 'true' : 'false';
			if ( $user->info->openid_url ) { $params['author-openid'] = $user->info->openid_url; }
		}

		// send document and check result
		list( $errcode, $result ) = $this->defensio->postDocument( $params );
		$status = (string)$result->status;
		if ( $errcode != 200 || ( $status != 'success' && $status != 'pending' ) ) {
			$msg = "Defensio error while submitting comment: $errcode $status $result->message\nWill queue to try again.";
			EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			$comment->status = self::COMMENT_STATUS_QUEUED;
			self::append_spamcheck( _t('Queued for Defensio scan.', 'defensio') );
			$comment->info->user_id = ($user instanceof User) ? $user->id : 0;
			$comment->update();
		}
		else {
			$comment->info->defensio_signature = (string)$result->signature;
			unset( $comment->info->user_id );
			if ( $status == 'pending' ) {
				EventLog::log( 'Comment posted, now pending', 'debug', 'plugin', 'Defensio' );
				$comment->status = self::COMMENT_STATUS_QUEUED;
				$comment->update();
			}
			else { // $status == 'success'
				EventLog::log( 'Comment posted, success', 'debug', 'plugin', 'Defensio' );
				$this->defensio_update_comment( $comment, $result );
			}
		}
	}

	/**
	 * Update the comment info and its status using the given Defensio data.
	 * @param Comment $comment The comment object to scan
	 * @param SimpleXMLElement $data The Defensio data
	 */
	private function defensio_update_comment( Comment $comment, SimpleXMLElement $data )
	{
		// copy the Defensio data
		$comment->info->defensio_allow           = $allow     =  (string)$data->allow == 'true';
		$comment->info->defensio_classification  = $type      =  (string)$data->classification; // legitimate, spam, and malicious
		$comment->info->defensio_spaminess       = $spaminess = ((string)$data->spaminess) * 100.0;
		$comment->info->defensio_profanity_match =               (string)$data->{'profanity-match'} == 'true';

		// see if it's spam or the spaminess is greater than min allowed spaminess
		$min_spaminess_flag = Options::get( self::OPTION_FLAG_SPAMINESS );
		$min_spaminess_delete = Options::get( self::OPTION_DELETE_SPAMINESS );
		if ( !$allow && $spaminess >= $min_spaminess_delete ) {
			$comment->delete();
		}
		else {
			if ( !$allow || $type != 'legitimate' ) { self::append_spamcheck( $comment, _t('Defensio flagged as \'%s\'',                 array( $type ),      'defensio') ); }
			if ( $spaminess > 0 )                   { self::append_spamcheck( $comment, _t('Defensio gave a spaminess rating of %.2f%%', array( $spaminess ), 'defensio') ); }

			if ( !$allow && $spaminess >= $min_spaminess_flag ) {
				$comment->status = 'spam';
			}
			else {
				// it's not spam so if auto_approve is set, approve it
				if ( Options::get( self::OPTION_AUTO_APPROVE ) ) {
					$comment->status = 'approved';
				}
				else {
					$comment->status = 'unapproved';
				}
			}
			$comment->update();
		}

		Cache::expire( 'defensio_stats' );
		Cache::expire( 'defensio_extended_stats' );
	}
	
	/**
	 * Add spamcheck entries to a comment.
	 * @param Comment $comment The comment to append spamcheck information to
	 * @param mixed $text Either an array of strings or a single string to append to the spamcheck list
	 */
	private static function append_spamcheck( Comment $comment, $text )
	{
		if ( is_string($text) ) {
			$text = array( $text );
		}
		if ( isset($comment->info->spamcheck) && is_array($comment->info->spamcheck) ) {
			$comment->info->spamcheck = array_unique( array_merge( $comment->info->spamcheck, $text ) );
		}
		else {
			$comment->info->spamcheck = $text;
		}
	}
	
	/**
	 * When comments are moderated send the results back to Defensio.
	 * @param string $action The moderation action - the only ones dealt with in this function are 'spam' and 'approve', all others are ignored
	 * @param Comments $comments The comments that are being moderated
	 * @param AdminHandler $handler The handler that is performing the moderation
	 */
	public function action_admin_moderate_comments( $action, Comments $comments, AdminHandler $handler )
	{
		// only opperate when becoming spam or approved
		if ( $action != 'spam' || $action != 'approve' ) { return; }
		
		$falses = 0;
		$allowed = $action == 'approve';

		// go through each comment and update it
		foreach ( $comments as $comment ) {
			if ( $this->defensio_update_status( $comment, $allowed ) ) {
				$falses++;
			}
		}

		// report on what was done
		$this->report_defensio_update( $allowed, $falses );
	}
	
	/**
	 * When comment status is updated, update Defensio
	 * @param Comment $comment The comment being updated
	 * @param mixed $old_value The old status value
	 * @param mixed $new_value The new status value
	 */
	public function action_comment_update_status( Comment $comment, $old_value, $new_value )
	{
		$new_value = Comment::status($new_value);
		$is_approved = $new_value == Comment::status('approved');
		$is_spam = $new_value == Comment::status('spam');
		if ( ($is_approved || $is_spam) && $this->defensio_update_status( $comment, $is_approved ) ) {
			$this->report_defensio_update( $allowed, 1 );
		}
	}
	
	/**
	 * Update the status of a comment with Defensio.
	 * @param Comment $comment The comment being updated
	 * @param bool $allowed If the new comment status is allowed (approved) or not (spam); the status unapproved should not be given
	 * @return bool If the Defensio status was updated and should be counted
	 */
	private function defensio_update_status( Comment $comment, $allowed )
	{
		if ( self::comment_age( $comment ) > self::MAX_COMMENT_DAYS ) {
			// too old
		}
		else if ( isset($comment->info->defensio_signature) ) {
			// ready or pending
			$ready = isset($comment->info->defensio_allow);
			if ( $ready && $comment->info->defensio_allow != $allowed || !$ready ) {
				// send update to Defensio
				list($errcode, $result) = $this->defensio->putDocument( $comment->info->defensio_signature, array( 'allow' => $allowed ? 'true' : 'false' ) );
				$status = (string)$result->status;
				if ( $errcode != 200 || ( $status != 'success' && $status != 'pending' ) ) {
					EventLog::log( "Failed to send updated status of comment: $errcode $status $result->message", 'warning', 'plugin', 'Defensio' );
				}
				else if ( $status != 'pending' ) {
					// update Defensio information
					$comment->info->defensio_allow          = (string)$result->allowed == 'true';
					$comment->info->defensio_classification = (string)$result->classification;
					return true;
				}
			}
		}
		else if ( $comment->status == self::COMMENT_STATUS_QUEUED ) {
			// never submitted
			//@todo
		}
		else {
			// not a Defensio comment
		}
		return false;
	}
	
	/**
	 * Report the results from a Defensio status update.
	 * @param bool $allowed If the new comment status was being set to allowed (approved) or not (spam)
	 * @param int $falses The number of updated Defensio statuses.
	 */
	private function report_defensio_update($allowed, $falses = 1)
	{
		if ( $falses > 0 ) {
			Cache::expire( 'defensio_stats' );
			Cache::expire( 'defensio_extended_stats' );
			$kind = $allowed ? 'positive' : 'negative';
			$msg = sprintf( _n( "Reported %d false $kind to Defensio", "Reported %d false {$kind}s to Defensio", $falses, 'defensio' ), $falses );
			EventLog::log( $msg, 'info', 'plugin', 'Defensio' );
			Session::notice( $msg );
		}
	}
	
	/**
	 * Gets the age of a comment in days.
	 * @param Comment $comment The comment to check
	 * @return int The number of days ago the comment was posted
	 */
	private static function comment_age( Comment $comment )
	{
		return intval((HabariDateTime::date_create('now')->int - $comment->date->int) / 86400);
	}
	
	
	////////// Announce Published Posts //////////

	// @todo work out some details here (insert_after, update_after, status_published ? )
	public function action_post_insert_after( Post $post ) { $this->announce_post($post); }
	public function action_post_update_after( Post $post ) { $this->announce_post($post); }

	/**
	 * Announces a post to Defensio, only if the user has enabled that optiona and the status is published.
	 * @param Post $post The post to announce.
	 */
	private function announce_post( Post $post )
	{
		if ( Options::get( self::OPTION_ANNOUNCE_POSTS ) && $post->status == Post::status( 'published' ) ) {
			// setup data to post
			$params = array(
				'platform' => 'habari',
				'type' => 'article',
				'author-name' => $post->author->displayname, // or username?
				'author-email' => $post->author->email,
				'document-permalink' => $post->permalink,
				'title' => $post->title,
				'content' => $post->content,
			);
			if ( $post->author->openid_url ) { $params['author-openid'] = $post->author->openid_url; }
			
			// submit
			list( $errcode, $result ) = $this->defensio->postDocument( $params );
			if ( $errcode != 200 || $result->status != 'success' ) {
				$msg = "Defensio error while announcing post: $errcode $result->status $result->message";
				EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			}
		}
	}
	
	
	////////// Commment Display //////////
	/**
	 * Add the 'defensio queue' comment status.
	 * @param array $comment_status_list The list of comment statuses
	 * @return array The list of comment statuses, with 'defensio queue' added
	 */
	public function filter_list_comment_statuses( array $comment_status_list )
	{
		$comment_status_list[self::COMMENT_STATUS_QUEUED] = 'defensio queue';
		return $comment_status_list;
	}
	
	/**
	 * Gets the style for a comment entry for admin view based on its spaminess and queued status.
	 * @param Comment $comment The comment to get the style for
	 * @return string The comment entry style
	 */
	public static function get_spaminess_style( Comment $comment )
	{
		if ( isset($comment->info->defensio_spaminess) && $comment->status == Comment::status('spam') ) {
			$grad_hex = create_function( '$s,$e,$i', 'return (($e-$s)*$i)+$s;' );
			$start_hex = '#FFD6D7';
			$end_hex = '#F8595D';
			$border = ColorUtils::rgb_hex(
				array_combine(
					array('r','g','b'),
					array_map(
						$grad_hex,
						ColorUtils::hex_rgb($start_hex),
						ColorUtils::hex_rgb($end_hex),
						array_fill(0, 3, $comment->info->defensio_spaminess / 100.0)
					)
				)
			);
			return "border-left-color:#$border; border-right-color:#$border;";
		}
		else if ( $comment->status == self::COMMENT_STATUS_QUEUED ) {
			return 'border-left: 3px solid #BCCFFF; border-right: 3px solid #BCCFFF;';
		}
		return '';
	}
	
	/**
	 * Adds the Defensio style to a comment when view in admin.
	 * @param string $style The current style of the comment
	 * @param Comment $comment The comment to get modify the style for
	 * @return string The style of the comment, augmented for spaminees and queued status
	 */
	public function filter_comment_style( $style, Comment $comment )
	{
		if ( $style != '' ) {
			$style .= ' ';
		}
		$style .= self::get_spaminess_style($comment);
		return $style;
	}
	
	/**
	 * Adds a spaminess label to to comments when view in admin. This is echoed directly.
	 * @param Comment $comment The comment to display the label for
	 */
	public function action_comment_info( Comment $comment )
	{
		if ( isset($comment->info->defensio_classification) ) {
			$start = '<p class="keyval' . ( $comment->info->defensio_classification == 'legitimate' ? '' : ' spam' ) . '"><span class="label">';
			if ( isset($comment->info->defensio_spaminess) ) {
				echo $start . _t('Defensio Spaminess:', 'defensio') . '</span><strong>' . $comment->info->defensio_spaminess . '%</strong></p>';
			}
			echo $start . _t('Defensio Type:', 'defensio') . '</span><strong>' . _t($comment->info->defensio_classification, 'defensio') . '</strong></p>';
		}
	}
	
	/**
	 * Sort by spaminess when the status:spam filter is set
	 * @todo use DB filters to sort from DB
	 */
	/* Throws an error when $comments is passed by reference. However, the entire purpose
	 * of the filter is to reorder the comments. Commenting out until a suitable fix can
	 * be found.
	public function filter_comments_actions( $actions, $comments )
	{
		if ( preg_match( '/status:\s*spam/i', Controller::get_handler()->handler_vars['search'] )
			|| Comment::status(Controller::get_handler()->handler_vars['status']) == Comment::status('spam') ) {
			usort( $comments, 'Defensio::sort_by_spaminess' );
		}
		return $actions;
	}*/

	public static function sort_by_spaminess( $a, $b )
	{
		if ( isset($a->info->defensio_spaminess) && isset($b->info->defensio_spaminess) ) {
			if ( $a->info->defensio_spaminess == $b->info->defensio_spaminess ) {
				return 0;
			}
			return $a->info->defensio_spaminess > $b->info->defensio_spaminess ? -1 : 1;
		}
		elseif ( isset($a->info->defensio_spaminess) ) {
			return 0;
		}
		else {
			return 100;
		}
	}
}

?>
