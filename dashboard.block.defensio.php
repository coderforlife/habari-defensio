<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
	<ul class="items">
<?php
if ($content->bad_response) {
    echo '<li class="item clear">' . _t('Bad Response From Server', 'defensio') . '</li>';
} else {
?>
		<li class="item clear">
			<span class="title pct80"><b>Recent Accuracy</b></span><span class="comments pct20"><?php echo $content->accuracy; ?>%</span>
		</li>
		<li class="item clear">
			<span class="pct80">Spam</span><span class="comments pct20"><?php echo $content->spam; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">Innocents</span><span class="comments pct20"><?php echo $content->ham; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">False Negatives</span><span class="comments pct20"><?php echo $content->false_negatives; ?></span>
		</li>
		<li class="item clear">
			<span class="pct80">False Positives</span><span class="comments pct20"><?php echo $content->false_positives; ?></span>
		</li>
<?php } ?>
	</ul>
