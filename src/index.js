// pull in desired CSS/SASS files
require( './styles/app.css' );
require('bootstrap');

var MainApp = require( './Main' );
MainApp.Main.embed( document.getElementById( 'main' ) );
