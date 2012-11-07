<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
<?php
if ( $content->error_msg ) {
    echo $content->error_msg;
} else {
    echo "<img src='{$content->charts['recent-accuracy']}' style='max-width:100%;max-height:100%;'>";
}
?>
