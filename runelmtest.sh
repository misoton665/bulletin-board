cd "$(dirname "$0")"
set -eu

cd ./src/test/

elm-package install -y
elm-make TestMain.elm --output=test.js --yes
node test.js
