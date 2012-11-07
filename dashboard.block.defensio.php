<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
	<ul class="items">
<?php
if ( $content->error_msg ) {
    echo '<li class="item clear">' . $content->error_msg . '</li>';
} else {
?>
		<li class="item clear">
			<span class="title pct80"><b>Recent Accuracy</b></span><span class="comments pct20"><?php echo sprintf( '%.2f', $content->accuracy); ?>%</span>
		</li>
		<li class="item clear">
			<span class="pct80">Spam</span><span class="comments pct20"><?php echo $content->spam; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">Malicious</span><span class="comments pct20"><?php echo $content->malicious; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">Innocents</span><span class="comments pct20"><?php echo $content->legitimate; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">False Negatives</span><span class="comments pct20"><?php echo $content->false_negatives; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">False Positives</span><span class="comments pct20"><?php echo $content->false_positives; ?></span>
		</li>
<?php if ( $content->learning ) { ?>
		<li class="item clear">
			<span class="pct80"><?php echo $content->learning_status; ?></span>
		</li>
<?php } ?>
<?php } ?>
	</ul>
