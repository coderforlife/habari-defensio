<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
<?php
if ( $content->error_msg ) {
	echo '<ul class="items"><li class="item clear">' . $content->error_msg . '</li></ul>';
}
else if ( $content->extended ) {
?>
<script type="text/javascript" src="https://www.google.com/jsapi"></script>
<script type="text/javascript">
google.load("visualization","1",{packages:["corechart"]});google.setOnLoadCallback(drawChart);
function drawChart(){
var v=google.visualization,d=new v.DataTable(),o={theme:"maximized",backgroundColor:"transparent",fontName:"inherit",fontSize:10,legend:{position:"none"},tooltip:{textStyle:{color:"#666"}},focusTarget:"category",hAxis:{format:"MMM-dd",gridlines:{color:"#DDD"},baselineColor:"#BBB",textStyle:{color:"#666"}},vAxis:{gridlines:{color:"#DDD"},baselineColor:"#BBB",textStyle:{color:"#666"}}};
d.addColumn("date","Date");
<?php
	if ( $content->display == 'recent_accuracy_plot' ) {
		echo 'd.addColumn("number","Accuracy");';
		echo 'd.addRows([';
		$use_min_96 = true;
		foreach ( $content->chart_data as $row ) {
			$date = explode( '-', $row['date'] );
			if ( $row['accuracy'] < 96.0 ) { $use_min_96 = false; }
			echo "[new Date($date[0]," . ( $date[1]-1 ) . ",{$date[2]})," . round($row['accuracy']/100.0,3) . '],';
		}
		echo ']);';
		echo 'new v.NumberFormat({pattern:"##0.0%"}).format(d,1);';
		echo 'o.colors=["#666"];';
		echo 'o.vAxis.format="##0%";';
		if ( $use_min_96 ) { echo 'o.vAxis.minValue=0.96;'; }
		echo 'o.vAxis.maxValue=1;';
	}
	else if ( $content->display == 'type_counts_plot' ) {
		echo 'd.addColumn("number","Unwanted");';
		echo 'd.addColumn("number","Legitimate");';
		echo 'd.addColumn("number","Mistakes");';
		echo 'd.addRows([';
		foreach ( $content->chart_data as $row ) {
			$date = explode( '-', $row['date'] );
			echo "[new Date($date[0]," . ( $date[1]-1 ) . ",{$date[2]}),{$row['unwanted']},{$row['legitimate']}," . ($row['false-positives']+$row['false-negatives']) . '],';
		}
		echo ']);';
        echo 'o.colors=["#A44","#484","#666"];';
	}
?>
new v.LineChart(document.getElementById('defensio_chart')).draw(d,o);
}
</script>
		<div id="defensio_chart" style="width:422px;height:196px;margin:0 auto;"></div>
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
