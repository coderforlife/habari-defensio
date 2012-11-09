<?php

require_once __DIR__ . '/Defensio.php';

/**
 * @package Defensio
 */
class Defensio extends Plugin
{
	const CHECK_FREQUENCY = 300; // 5 min
	const MAX_COMMENT_DAYS = 30;
	const COMMENT_STATUS_QUEUED = 9;

	const DEFENSIO_CLIENT_ID = 'Habari Defensio Plugin | 2.0 | Jeffrey Bush | jeff@coderforlife.com';

	const OPTION_MY_ID = 'defensio__my_id'; // used to uniquely identify this installation to prevent hacking
	const OPTION_API_KEY = 'defensio__api_key';
	const OPTION_FLAG_SPAMINESS = 'defensio__spaminess_flag';
	const OPTION_DELETE_SPAMINESS = 'defensio__spaminess_delete';
	const OPTION_ANNOUNCE_POSTS = 'defensio__announce_posts';
	const OPTION_AUTO_APPROVE = 'defensio__auto_approve';
	const OPTION_PROFANITY_FILTER_AUTHOR = 'defensio__profanity_filter_author';
	const OPTION_PROFANITY_FILTER_CONTENT = 'defensio__profanity_filter_content';
	const OPTION_PLOT_DAYS = 'defensio__plot_days';

	private $defensio;
	
	/**
	 * Handle an Exception raised by the Defensio API functions. This will log a warning message and return it.
	 * @param Exception $ex The exception that was raised
	 * @return string The message written to the log
	 */
	private function handle_defensio_exception( Exception $ex )
	{
		if ( $ex instanceof DefensioConnectionTimeout ) {
			$msg = $ex->getMesasge() ?
				_t('Connection timed out', 'defensio') . ":\n" . $ex->getMesasge() . "\n$ex->error_code: $ex->error_string" :
				_t('Connection timed out', 'defensio');
		}
		else if ( $ex instanceof DefensioConnectionError ) {
			$msg = _t('Connection error', 'defensio') . ":\n" . $ex->getMesasge() . "\n$ex->error_code: $ex->error_string";
		}
		else if ( $ex instanceof DefensioEmptyCallbackData ) {
			$msg = _t('Defensio callback data was empty');
		}
		// Use the just the given message for DefensioInvalidKey, DefensioUnexpectedHTTPStatus, DefensioFail
		else {
			$msg = $ex->getMesasge();
		}
		EventLog::log( $msg , 'warning', 'plugin', 'Defensio' );
		return $msg;
	}
	
	/**
	 * Get the XML response from a Defensio API function.
	 * @param string $func The name of the Defensio API function
	 * @param string $desc What this function does (fills in the sentence "while ...")
	 * @param array $params The parameters to pass to the function, default no paremeters (empty array)
	 * @param array $allowed_statuses The statuses that are allowed as "successful" (default is just 'success', some functions will need 'pending' as well)
	 * @return mixed If there is a problem then a string with the error message is returned, otherwise the SimpleXMLElement object with the response.
	 */
	private function get_defensio_xml( $func, $desc, array $params = array(), array $allowed_statuses = array('success') )
	{
		try {
			list( $http_status, $xml ) = call_user_func_array( array( $this->defensio, $func ), $params );
			if ( $http_status != 200 || !in_array( (string)$xml->status, $allowed_statuses ) ) {
				$msg = _t("<b>Defensio Error while $desc:</b> %d %s %s", array($http_status, $xml->status, $xml->message), 'defensio');
				EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
				return $msg;
			}
			return $xml;
		}
		catch ( Exception $ex ) {
			return _t('<b>Defensio Server Error:</b> %s', array( $this->handle_defensio_exception( $ex ) ), 'defensio');
		}
	}
	

	////////// Basic Setup and Initialization //////////

	/**
	 * Setup defaults on activation. Don't overwrite settings if they are already there. Start Defensio Queue.
	 */
	public function action_plugin_activation()
	{
		Session::notice( _t('Please set your Defensio API Key in the configuration.', 'defensio') );
		Options::set( self::OPTION_MY_ID, self::rand_id() );
		if ( is_null(Options::get(self::OPTION_API_KEY)) ) {
			Options::set( self::OPTION_API_KEY, '' );
		}
		if ( is_null(Options::get(self::OPTION_FLAG_SPAMINESS)) ) {
			Options::set(self::OPTION_FLAG_SPAMINESS, 0); // WordPress default is 80%? Or does that no longer apply for API 2.0?
		}
		if ( is_null(Options::get(self::OPTION_DELETE_SPAMINESS)) ) {
			Options::set(self::OPTION_DELETE_SPAMINESS, 99);
		}
		if ( is_null(Options::get(self::OPTION_ANNOUNCE_POSTS)) ) {
			Options::set(self::OPTION_ANNOUNCE_POSTS, true);
		}
		if ( is_null(Options::get(self::OPTION_AUTO_APPROVE)) ) {
			Options::set(self::OPTION_AUTO_APPROVE, false);
		}
		if ( is_null(Options::get(self::OPTION_PROFANITY_FILTER_AUTHOR)) ) {
			Options::set(self::OPTION_PROFANITY_FILTER_AUTHOR, false);
		}
		if ( is_null(Options::get(self::OPTION_PROFANITY_FILTER_CONTENT)) ) {
			Options::set(self::OPTION_PROFANITY_FILTER_CONTENT, false);
		}
		if ( is_null(Options::get(self::OPTION_PLOT_DAYS)) ) {
			Options::set(self::OPTION_PLOT_DAYS, 30);
		}
		
		CronTab::add_cron(array(
			'name' => 'defensio_queue',
			'callback' => 'defensio_queue',
			'increment' => self::CHECK_FREQUENCY,
			'cron_class' => CronJob::CRON_PLUGIN,
			'description' => _t('Scan comments with Defensio that were pending and failed queued the first time', 'defensio'),
		));
	}

	/**
	 * Stop Defensio Queue upon deactivation.
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
	}

	/**
	 * Generates a random ID that is 32 hex characters long (representing 16 bytes or 128 bits).
	 * @return string 32 character hex string
	 */
	private static function rand_id()
	{
		$id = '';
		for ($i = 0; $i < 8; $i++) {
			$id .= str_pad(dechex(mt_rand(0x0000, 0xFFFF)), 4, 0, STR_PAD_LEFT);
		}
		return $id;
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
		$spaminess_opts = array_combine(array_merge($spaminess_values, array(99, 100)), array_merge($spaminess_keys, array('99%', 'Never')));
		
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
		$ui->append( 'static', 'register', '<div><label><a href="http://defensio.com/signup" target="_blank">' . _t('Get a new Defensio API key.', 'defensio') . '</a></label></div><hr>' );

		// min spaminess flag
		$spaminess_flag = $ui->append(
				'select',
				'min_spaminess_flag',
				'option:' . self::OPTION_FLAG_SPAMINESS,
				_t('Minimum Spaminess* to Flag as Spam: ', 'defensio')
			);
		$spaminess_flag->options = $spaminess_opts;

		// min spaminess for automatic deletion
		$spaminess_delete = $ui->append(
				'select',
				'min_spaminess_delete',
				'option:' . self::OPTION_DELETE_SPAMINESS,
				_t('Minimum Spaminess* to Automatically Delete: ', 'defensio')
			);
		$spaminess_delete->options = $spaminess_opts;

		$ui->append( 'static', 'extra', '<div><label>' . _t('* If and only if Defensio also flags the comment as spam. See (?) for more information.', 'defensio') . '</label></div><hr>' );


		// checkboxes
		$announce_posts = $ui->append( 'checkbox', 'announce_posts', 'option:' . self::OPTION_ANNOUNCE_POSTS,           _t('Announce New Posts To Defensio: ',          'defensio') );
		$auto_approve   = $ui->append( 'checkbox', 'auto_approve',   'option:' . self::OPTION_AUTO_APPROVE,             _t('Automatically Approve Non-Spam Comments: ', 'defensio') );
		$filter_author  = $ui->append( 'checkbox', 'filter_author',  'option:' . self::OPTION_PROFANITY_FILTER_AUTHOR,  _t('Filter Profanity in Comment Author: ',      'defensio') );
		$filter_content = $ui->append( 'checkbox', 'filter_content', 'option:' . self::OPTION_PROFANITY_FILTER_CONTENT, _t('Filter Profanity in Comment Content: ',     'defensio') );

		$ui->append( 'static', 'divider', '<hr>' );

		// plot option
		$num_of_days = $ui->append( 'text', 'num_of_days', 'option:' . self::OPTION_PLOT_DAYS, _t('Maximum number of days to plot:', 'defensio') );
		$num_of_days->add_validator( 'validate_regex', '/^0*([1-9]|[1-2][0-9]|30)$/', _t('Only integers between 1 and 30 may be entered for number of days to plot.', 'defensio') );
		$num_of_days->add_validator( 'validate_range', 1, 30, _t('Number of days to plot must be between 1 and 30.', 'defensio') );

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
		Cache::expire( 'defensio_extended_stats' );
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
		try {
			list( $http_status, $xml ) = $defensio->getUser();
			if ( $http_status == 200 && (string)$xml->status == 'success' ) {
				return self::trim_hostname( $xml->{'owner-url'} ) == $host ? array() :
					array(_t('Sorry, the Defensio API key <b>%s</b> is not registered for this site (%s).', array( $key, $host ), 'defensio'));
			}
			else { // $http_status == 404 or status is 'failed'
				return array(_t('Sorry, the Defensio API key <b>%s</b> is invalid. Please check to make sure the key is entered correctly. Defensio said: "%s"', array( $key, $xml->message ), 'defensio'));
			}
		}
		catch ( Exception $ex ) {
			return array(_t('<b>Defensio Server Error:</b> %s', array($this->handle_defensio_exception($ex)), 'defensio'));
		}
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
		return $block_list;
	}
	
	/**
	 * Produce the content for the Defensio block
	 * @param Block $block The block object
	 * @param Theme $theme The theme that the block will be output with
	 */
	public function action_block_content_defensio( $block, Theme $theme )
	{
		if ( !isset($block->display) || $block->display == 'basic' ) {
			$extended = false;
			$display = 'basic';
			$block->title = 'Defensio';
		}
		else {
			$extended = true;
			$display = $block->display;
			$titles = array(
				'recent_accuracy_plot' => 'Recent Accuracy'
			);
			$block->title = 'Defensio: '.$titles[$display];
		}
		
		$stats = $extended ? $this->defensio_recent_extended_stats() : $this->defensio_stats();
		// show an error in the dashboard if Defensio returns a bad response.
		if ( is_string($stats) ) { $block->error_msg = $stats; return; }

		$block->error_msg = null;
		$block->extended = $extended;
		$block->display = $display;
		
		if ( $extended ) {
			$charts = array();
			foreach ($stats->{'chart-urls'}->children() as $chart_url) {
				$charts[$chart_url->getName()] = (string)$chart_url;
			}
			$block->charts = $charts;
			
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
			$block->chart_data = $data;
		}
		else {
			$block->accuracy        = ((string)$stats->accuracy) * 100.0;
			$block->spam            = ((string)$stats->unwanted->spam) * 1;
			$block->malicious       = ((string)$stats->unwanted->malicious) * 1;
			$block->legitimate      = ((string)$stats->legitimate->total) * 1;
			$block->false_negatives = ((string)$stats->{'false-negatives'}) * 1;
			$block->false_positives = ((string)$stats->{'false-positives'}) * 1;
			$block->learning        =  (string)$stats->learning == 'true';
			$block->learning_status =  (string)$stats->{'learning-status'};
		}

		$block->link = URL::get('admin', array('page' => 'comments'));
		$block->has_options = true;
	}

	/**
	 * The options panel for the Defensio block.
	 * @param FormUI $form The form that will set the options
	 * @param Block $block The block that we set the options for
	 */
	public function action_block_form_defensio( FormUI $form, $block )
	{
		$display = $form->append( 'select', 'display', $block, _t('Display:', 'defensio') );
		$display->options = array(
			'basic' => 'Basic',
			'recent_accuracy_plot' => 'Recent Accuracy Plot'
		);		
		$form->append( 'submit', 'submit', _t('Submit') );
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
			$stats = $this->get_defensio_xml( 'getBasicStats', 'getting stats' );
			if ( !is_string($stats) ) {
				Cache::set( 'defensio_stats', $stats->asXML() );
			}
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
		
		return $this->get_defensio_xml( 'getExtendedStats', 'getting extended stats', array( array( 'from' => $from, 'to' => $to ) ) );
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
			$stats = $this->defensio_extended_stats( strtotime( '-' . Options::get(self::OPTION_PLOT_DAYS) . ' days'), time() );
			if ( !is_string($stats) ) {
				Cache::set( 'defensio_extended_stats', $stats->asXML() );
			}
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
		$filtered = $this->get_defensio_xml( 'postProfanityFilter', 'getting extended stats', array( $in ) );
		if ( is_string($filtered) ) {
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
				EventLog::log( _t( 'Defensio comment submission was pending or failed for 30 days. Will not try again.', 'defensio' ), 'warning', 'plugin', 'Defensio' );
			}
			else if ( isset($comment->info->defensio_signature) ) {
				
				// check pending asynchronous result
				$result = $this->get_defensio_xml( 'getDocument', 'getting comment results', array( $comment->info->defensio_signature ), array( 'success', 'pending' ) );
				if ( !is_string($result) ) {
					if ( (string)$result->status == 'success' ) {
						$this->defensio_update_comment( $comment, $result );
					}
					else {
						// else still pending
					}
				}

			}
			else {
				
				// resubmit failed attempt
				$this->defensio_post_comment( $comment, User::get_by_id($comment->info->user_id) );
				
			}
		}
		return $cron_result;
	}

	/**
	 * Add the Defensio callback rewrite rule.
	 * @param array $rules The unfiltered rewrite rules
	 * @return array The rewrite rules with the Defensio callback added
	 */
	public function filter_rewrite_rules( array $rules )
	{
		$myid = Options::get( self::OPTION_MY_ID );
		$rules[] = new RewriteRule(array(
			'name'=>'defensio_callback',
			'handler'=>'PluginHandler',
			'action'=>'defensio_callback',
			'priority'=>6,
			'parse_regex'=>'%^defensio_callback~' . $myid . '~(?P<comment_id>[0-9]+)/?$%i',
			'build_str'=>'defensio_callback~' . $myid . '~{$comment_id}/',
		));
		return $rules;
	}
	
	/**
	 * Process the Defensio callback.
	 * @param ActionHandler $handler The handler that processed the URL, used to get the comment ID
	 */
 	public function action_plugin_act_defensio_callback( ActionHandler $handler )
	{
		$id = $handler->handler_vars['comment_id'] * 1;
		$comment = Comment::get( $handler->handler_vars['comment_id'] * 1 );
		if ( !$comment ) {
			EventLog::log( _t('Defensio callback had invalid comment ID: %d', array( $id ), 'defensio' ), 'warning', 'plugin', 'Defensio' );
		}
		else {
			$result = $this->get_defensio_xml( 'handlePostDocumentAsyncCallback', 'in callback' );
			if ( !is_string($result) ) {
				if ( !isset($comment->info->defensio_signature) || $comment->info->defensio_signature != (string)$result->signature ) {
					EventLog::log( _t( 'Defensio signature (%s) and comment ID (%d) do not correspond', array( (string)$result->signature, $id ), 'defensio' ), 'warning', 'plugin', 'Defensio' );
				}
				else {
					EventLog::log( _t( 'Defensio callback is running', 'defensio' ), 'debug', 'plugin', 'Defensio' );
					$this->defensio_update_comment( $comment, $result );
				}
			}
		}
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
			'async-callback' => URL::get( 'defensio_callback', array('comment_id' => $comment->id) ),
			
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
		$result = $this->get_defensio_xml( 'postDocument', 'postting comment', array( $params ), array( 'success', 'pending' ) );
		if ( is_string($result) ) {
			// will queue to try again?
			EventLog::log( _t( 'Defensio failed - will retry', 'defensio' ), 'debug', 'plugin', 'Defensio' );
			$comment->status = self::COMMENT_STATUS_QUEUED;
			self::append_spamcheck( $comment, _t('Queued for Defensio scan.', 'defensio') );
			$comment->info->user_id = ($user instanceof User) ? $user->id : 0;
			$comment->update();
		}
		else {
			$comment->info->defensio_signature = (string)$result->signature;
			unset( $comment->info->user_id );
			if ( (string)$result->status == 'pending' ) {
				self::append_spamcheck( $comment, _t('Queued for Defensio pending scan results.', 'defensio') );
				$comment->status = self::COMMENT_STATUS_QUEUED;
				$comment->update();
			}
			else { // $result->status == 'success'
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
			EventLog::log( _t( 'Auto-deleting comment', 'defensio' ), 'debug', 'plugin', 'Defensio' );
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
				$result = $this->get_defensio_xml( 'putDocument', 'updatint status of comment', array( $comment->info->defensio_signature, array( 'allow' => $allowed ? 'true' : 'false' ) ), array( 'success', 'pending' ) );
				if ( !is_string($result) && (string)$result->status != 'pending' ) {
					// update Defensio information
					EventLog::log( _t( 'Updated Defensio status of comment', 'defensio' ), 'debug', 'plugin', 'Defensio' );
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
			$this->get_defensio_xml( 'postDocument', 'announcing post', array( $params ) );
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
