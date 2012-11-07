<?php if ( !defined( 'HABARI_PATH' ) ) { die( 'No direct access' ); } ?>
<?php
if ( $content->error_msg ) {
    echo $content->error_msg;
} else {
    echo $content->charts['recent-accuracy'];
}
?>
