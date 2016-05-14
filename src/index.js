// pull in desired CSS/SASS files
require( './styles/app.css' );
require('bootstrap');

var Elm = require( './Main' );
Elm.Main.embed( document.getElementById( 'main' ) );
