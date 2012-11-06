<?php

require_once __DIR__ . '/Defensio.php';

/**
 * @package Defensio
 */
class Defensio extends Plugin
{
	const MAX_RETRIES = 10;
	const RETRY_INTERVAL = 30;
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

	/**
	 * Set the priority of 'action_comment_insert_before' to 1, so we are close to first to run
	 * before Comment insertion.
	 * @return array The customized priority
	 */
	public function set_priorities()
	{
		return array(
			'action_comment_insert_before' => 1
		);
	}

	/**
	 * Setup defaults on activation. Don't overwrite API key if it's already there.
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
	}

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

		// Add a text control for the address you want the email sent to
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
		$host = trim_hostname( Site::get_url( 'hostname' ) );
		$defensio = new DefensioAPI( $key, self::DEFENSIO_CLIENT_ID );
		list( $errcode, $xml ) = $defensio->getUser();
		if ( $errcode == 200 && $xml->status == 'success' ) {
			return trim_hostname( $xml->{'owner-url'} ) == $host ? array() :
				array(_t('Sorry, the Defensio API key <b>%s</b> is not registered for this site (%s).', array( $key, $host ), 'defensio'));
		}
		return array(_t('Sorry, the Defensio API key <b>%s</b> is invalid. Please check to make sure the key is entered correctly. Defensio said: "%s"', array( $key, $xml->message ), 'defensio'));
	}

	/**
	 * Setup the Defensio API on Habari initialization.
	 * @todo move text domain loading to only admin.
	 */
	public function action_init()
	{
		$this->defensio = new DefensioAPI( Options::get( self::OPTION_API_KEY ), self::DEFENSIO_CLIENT_ID );
		$this->load_text_domain( 'defensio' );
		$this->add_template( 'dashboard.block.defensio', __DIR__ . '/dashboard.block.defensio.php' );
	}
	
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
		$block->link = URL::get('admin', array('page' => 'comments'));

		$stats = $this->defensio_stats();
		// Show an error in the dashboard if Defensio returns a bad response.
		if ( is_string($stats) ) { $block->error_msg = $stats; return; }

		$block->error_msg = null;
		$block->accuracy = sprintf( '%.2f', (string)$stats->accuracy * 100 );
		$block->spam = (string)$stats->unwanted->spam;
		$block->malicious = (string)$stats->unwanted->malicious;
		$block->legitimate = (string)$stats->legitimate->total;
		$block->false_negatives = (string)$stats->{'false-negatives'};
		$block->false_positives = (string)$stats->{'false-positives'};
		$block->learning = (string)$stats->learning;
		$block->learning_status = (string)$stats->{'learning-status'};
	}
	
	/**
	 * Get the basic Defensio stats.
	 * @return mixed The stats as SimpleXMLElement or a string with an error message.
	 */
	public function defensio_stats()
	{
		if ( Cache::has( 'defensio_stats' ) ) {
			$stats = simplexml_load_string( Cache::get( 'defensio_stats' ) );
		}
		else {
			list( $errcode, $stats ) = $this->defensio->getBasicStats();
			if ( $errcode != 200 || (string)$stats->status != 'success' ) {
				$msg = "Defensio error while getting stats: $errcode $stats->message";
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
	 * @todo add caching (at least for most recent one)
	 * @todo display somewhere
	 * @return mixed The stats as SimpleXMLElement or a string with an error message.
	 */
	public function defensio_extended_stats($from, $to = null)
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
			$msg = "Defensio error while getting extended stats: $errcode $stats->message";
			EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			return $msg;
		}

		return $stats;
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
		list( $errcode, $filtered ) = $this->defensio->postProfanityFilter( $in );
		if ( $errcode != 200 || (string)$filtered->status != 'success' ) {
			$msg = "Defensio error while running profanity filter: $errcode $filtered->message";
			EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			return $data;
		}
		
		if ( is_string($data) )
			return (string)$filtered->filtered->text;
		$out = array();
		foreach ( $map as $key_xml => $key )
			$out[$key] = (string)$filtered->filtered->$key_xml;
		return $out;
	}
	
	/**
	 * @todo cache results (at least for this iteration)
	 * @todo use defensio_profanity_match
	 */
	public function filter_comment_content_out($content, $comment)
	{
		if ( Options::get( self::OPTION_PROFANITY_FILTER_CONTENT ) ) {
			$content = $this->defensio_profanity_filter( $content );
		}
		return $content;
	}

	/**
	 * @todo cache results (at least for this iteration)
	 */
	public function filter_comment_name_out($name, $comment)
	{
		if ( Options::get( self::OPTION_PROFANITY_FILTER_AUTHOR ) ) {
			$name = $this->defensio_profanity_filter( $name );
		}
		return $name;
	}
	
	/**
	 * Scan a comment with Defensio and dissallow it if its spaminess is above threshold.
	 * @param Comment $comment The comment object to scan
	 */
	public function filter_comment_insert_allow( $allow, $comment )
	{
		$user = User::identify();
		$params = array(
			'platform' => 'habari',
			'type' => strtolower( $comment->typename ), // one of: comment*, trackback*, pingback*, article, wiki, forum, other, test
			
			// @todo fill these in
			//'browser-cookies' => 
			//'browser-javascript' => 

			'parent-document-date' => $comment->post->pubdate->format( 'Y-m-d' ),
			'parent-document-permalink' => $comment->post->permalink,

			'author-name' => $comment->name,
			'author-ip' => is_string( $comment->ip ) && strpos( $comment->ip, '.' ) > 0 ? $comment->ip : long2ip( $comment->ip ),
			// @todo is there any way around the id issue?
			//'document-permalink' => $comment->post->permalink.'#comment-'.$comment->id, // 'id' not available until after insertion
			//'title' => ... // comments have no title
			'content' => $comment->content,
		);
		
		// Set HTTP header fields
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
		$headers = @getallheaders();
		if ($headers !== FALSE) {
			foreach ( $headers as $key => $value ) {
				$http_headers[str_replace('-', '_', strtoupper($key))] = $value;
			}
		}
		$http_headers_text = '';
		foreach ( $http_headers as $key => $value ) {
			$http_headers_text .= "$key: $value\n";
		}
		$params['http-headers'] = trim($http_headers_text);

		// Set additional, conditional, fields
		if ( $comment->email ) { $params['author-email'] = $comment->email; }
		if ( $comment->url )   { $params['author-url'] = $comment->url; }
		if ( $user instanceof User ) {
			$params['author-logged-in'] = $user->loggedin ? 'true' : 'false';
			// @todo test for administrator, editor, etc. as well
			$params['author-trusted'] = $user->loggedin ? 'true' : 'false';
			if ( $user->info->openid_url ) { $params['author-openid'] = $user->info->openid_url; }
		}

		list( $errcode, $result ) = $this->defensio->postDocument( $params );
		if ( $errcode != 200 || (string)$result->status != 'success' ) { // with async 'pending' is a valid option
			//$msg = "Defensio error while getting extended stats: $errcode $stats->message";
			//EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			//return $msg;
		}

		$comment->info->defensio_signature = (string)$result->signature;
		// all empty while 'pending':
		$comment->info->defensio_allow = (string)$result->allow == 'true';
		$comment->info->defensio_classification = (string)$result->classification; // innocent, spam, and malicious
		$comment->info->defensio_spaminess = (string)$result->spaminess * 1.0;
		$comment->info->defensio_profanity_match = (string)$result->{'profanity-match'} == 'true';

		// don't auto-delete logged-in users
		if ( $user->loggedin ) { return $allow; }
		
		// see if it's spam or the spaminess is greater than min allowed spaminess
		$min_spaminess_delete = Options::get( self::OPTION_DELETE_SPAMINESS );
		if ( !$comment->info->defensio_allow && $comment->info->defensio_spaminess >= ((int) $min_spaminess_delete / 100) ) { return false; }

		return $allow;
	}

	/**
	 * Use the already computed Defensio data to determine if a comment is spam, unapproved, or approved.
	 * @param Comment $comment The comment object to scan
	 */
	private function audit_comment( Comment $comment )
	{
		// see if it's spam or the spaminess is greater than min allowed spaminess
		$min_spaminess_flag = Options::get( self::OPTION_FLAG_SPAMINESS );
		if ( !$comment->info->defensio_allow && $comment->info->defensio_spaminess >= ((int) $min_spaminess_flag / 100) ) {
			$comment->status = 'spam';
			// this array nonsense is dumb
			$comment->info->spamcheck = array_unique(
				array_merge(
					(array) $comment->info->spamcheck,
					array( _t('Flagged as Spam by Defensio', 'defensio') )
				)
			);
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
	}

	/**
	 * Hook in to scan the comment with Defensio. If it fails, add a cron to try again.
	 * @param Comment $comment The comment object that was inserted
	 */
	public function action_comment_insert_before( Comment $comment )
	{
		//try {
			$this->audit_comment( $comment );
		/*}
		catch ( Exception $e ) {
			EventLog::log(
				_t('Defensio scanning for comment %s failed, adding to queue', array($comment->ip), 'defensio'),
				'notice', 'comment', 'Defensio'
			);
			$comment->status =  self::COMMENT_STATUS_QUEUED;
			$comment->info->spamcheck = array( _t('Queued for Defensio scan.', 'defensio') );
			// this could cause multiple crons without checking if there, but that's ok, it'll avoid races.
			$this->_add_cron();
			Session::notice( _t('Your comment is being scanned for spam.', 'defensio') );
		}*/
	}
	
	/**
	 * I should really comment all these functions. --matt
	 */
	/*protected function _add_cron( $time = 0 )
	{
		CronTab::add_single_cron(
				'defensio_queue',
				'defensio_queue',
				time() + $time,
				_t('Queued comments to scan with defensio, that failed first time', 'defensio')
			);
	}*/
	
	/**
	 * try to scan for MAX_RETRIES
	 */
	/*public function filter_defensio_queue($result = true)
	{
		$comments = Comments::get( array('status' => self::COMMENT_STATUS_QUEUED) );
		
		if ( count($comments) > 0 ) {
			$try_again = FALSE;
			foreach( $comments as $comment ) {
				// Have we tried yet
				if ( !$comment->info->defensio_retries ) {
					 $comment->info->defensio_retries = 1;
				}
				try {
					$this->audit_comment( $comment );
					$comment->update();
					EventLog::log(
						_t('Defensio scanning, retry %d, for comment %s succeded', array($comment->info->defensio_retries, $comment->ip), 'defensio'),
						'notice', 'plugin', 'Defensio'
					);
				}
				catch ( Exception $e ) {
					if ( $comment->info->defensio_retries == self::MAX_RETRIES ) {
						EventLog::log(
							_t('Defensio scanning failed for comment %s. Could not connect to server. Marking unapproved.', array($comment->ip), 'defensio'),
							'notice', 'plugin', 'Defensio'
						);
						$comment->status = 'unapproved';
						$comment->update();
					}
					else {
						EventLog::log(
							_t('Defensio scanning, retry %d, for comment %s failed', array($comment->info->defensio_retries, $comment->ip), 'defensio'),
							'notice', 'plugin', 'Defensio'
						);
						// increment retries and set try_again
						$comment->info->defensio_retries = $comment->info->defensio_retries + 1;
						$comment->update();
						$try_again = TRUE;
					}
				}
			}
			// try again in RETRY_INTERVAL seconds if not scanned yet
			if ( $try_again ) {
				$this->_add_cron(self::RETRY_INTERVAL);
			}
		}
		return true;
	}*/

	public function action_admin_moderate_comments( $action, Comments $comments, AdminHandler $handler )
	{
		$false_positives = 0;
		$false_negatives = 0;

		foreach ( $comments as $comment ) {
			switch ( $action ) {
				case 'spam':
					if ( isset($comment->info->defensio_allow) && $comment->info->defensio_allow ) {
						list($errcode, $xml) = $this->defensio->putDocument( $comment->info->defensio_signature, array( 'allow' => 'false' ) );
						if ( $errcode != 200 ) {
							EventLog::log( "Failed to send updated allowed status of comment: $errcode $xml->message", 'warning', 'plugin', 'Defensio' );
						}
						else {
							$comment->info->defensio_allow = false;
							$false_negatives++;
						}
					}
					break;
				case 'approve':
					if ( isset($comment->info->defensio_allow) && !$comment->info->defensio_allow ) {
						list($errcode, $xml) = $this->defensio->putDocument( $comment->info->defensio_signature, array( 'allow' => 'true' ) );
						if ( $errcode != 200 ) {
							EventLog::log( "Failed to send updated allowed status of comment: $errcode $xml->message", 'warning', 'plugin', 'Defensio' );
						}
						else {
							$comment->info->defensio_allow = true;
							$false_positives++;
						}
					}
					break;
			}
		}

		if ( $false_positives > 0 || $false_negatives > 0 ) {
			Cache::expire('defensio_stats');
			EventLog::log(_t('Reported %d false positive(s) and %d false negative(s) to Defensio', array($false_positives, $false_negatives), 'defensio'), 'info', 'plugin', 'Defensio');
		}
	}

	public function announce_post( Post $post )
	{
		if ( Options::get( self::OPTION_ANNOUNCE_POSTS ) && $post->status == Post::status( 'published' ) ) {
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
			
			list( $errcode, $result ) = $this->defensio->postDocument( $params );
			if ( $errcode != 200 || $result->status != 'success' ) {
				$msg = "Defensio error while announcing post: $errcode $result->message";
				EventLog::log( $msg, 'warning', 'plugin', 'Defensio' );
			}
		}
	}
	public function action_post_insert_after( Post $post ) { $this->announce_post($post); }
	public function action_post_update_after( Post $post ) { $this->announce_post($post); }
	
	public function filter_list_comment_statuses( array $comment_status_list )
	{
		$comment_status_list[self::COMMENT_STATUS_QUEUED] = 'defensio queue';
		return $comment_status_list;
	}
	
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
						array_pad(array(), 3, $comment->info->defensio_spaminess)
					)
				)
			);
			return "border-left-color:#$border; border-right-color:#$border;";
		}
		elseif ( $comment->status == self::COMMENT_STATUS_QUEUED ) {
			return 'border-left: 3px solid #BCCFFF; border-right: 3px solid #BCCFFF;';
		}
		return '';
	}
	
	public function filter_comment_style( $style, Comment $comment )
	{
		if ( $style != '' ) {
			$style .= ' ';
		}
		$style .= self::get_spaminess_style($comment);
		return $style;
	}
	
	public function action_comment_info( Comment $comment )
	{
		if ( isset($comment->info->defensio_spaminess) ) {
			echo '<p class="keyval spam"><span class="label">' . _t('Defensio Spaminess:', 'defensio') . '</span>' . '<strong>' . ($comment->info->defensio_spaminess*100) . '%</strong></p>';
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
			return 1;
		}
	}
}

?>
