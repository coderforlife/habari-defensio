<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
<?php
if ( $content->error_msg ) {
	echo '<ul class="items"><li class="item clear">' . $content->error_msg . '</li></ul>';
}
else if ( $content->extended ) {
?>
		<script type="text/javascript" src="https://www.google.com/jsapi"></script>
	    <script type="text/javascript">
		google.load('visualization','1',{packages:["corechart"]});
		google.setOnLoadCallback(drawChart);
		function drawChart() {
			var data=new google.visualization.DataTable();
			data.addColumn('date','Date');
			data.addColumn('number','Accuracy');
			data.addRows([<?php
$use_min_95 = true;
foreach ($data as $row) {
	$date = explode('-', $row['date']);
	if ($row['accuracy'] < 95.0) { $use_min_95 = false; }
	echo "[new Date($date[0],".($date[1]-1).",{$date[2]}),".round($row['accuracy']/100.0,3).'],';
}
?>]);
			new google.visualization.NumberFormat({pattern:'##0.0%'}).format(data, 1);
			var options={theme:'maximized',backgroundColor:'transparent',fontName:'inherit',fontSize:10,
				series:[{color:'black',visibleInLegend:false}],
				hAxis:{format:'MMM-dd'},vAxis:{<?php echo $use_min_95 ? 'minValue:0.95,' : ''; ?>maxValue:1,format:'##0.0%'},
			};
			var chart=new google.visualization.LineChart(document.getElementById('chart_div'));
			chart.draw(data,options);
		}
		</script>
		<div id="defensio_chart" style="width:94%;height:90%;margin:2.5% auto;"></div>
<?php
}
else { // basic display
?>
	<ul class="items">
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
	</ul>
<?php } ?>
<?php } ?>
