import Html.App as Html

import Components.Model exposing (initialModel)
import Components.View exposing (view)
import Components.Update exposing (update)

-- APP
main : Program Never
main =
  Html.beginnerProgram { model = initialModel, view = view, update = update }
