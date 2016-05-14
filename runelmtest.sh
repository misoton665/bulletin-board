cd "$(dirname "$0")"
set -eu

cd ./src/test/

elm-package install -y
elm-make TestMain.elm --output=../../tmp/test.js --yes
node ../../tmp/test.js
